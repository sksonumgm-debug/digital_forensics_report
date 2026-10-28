import os
import re
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as application
import pyotp
from database import (
    create_user,
    get_case,
    add_audit,
    add_events,
    add_disk_image,
    cancel_background_job,
    claim_background_job,
    connect,
    enqueue_background_job,
    get_background_job,
    get_disk_image,
    get_user_by_id,
    get_user_by_username,
    get_workspace_review_summary,
    init_db,
    recover_background_jobs,
    retry_background_job,
    save_finding_feedback,
    update_background_job,
    verify_audit_chain,
)
from werkzeug.security import generate_password_hash


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = application.DB_PATH
        application.DB_PATH = os.path.join(self.temp_dir.name, "test.sqlite3")
        init_db(application.DB_PATH)
        application.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = application.app.test_client()

    def tearDown(self):
        application.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def csrf_token(self, client, path="/login"):
        response = client.get(path)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        match = re.search(rb'name="csrf-token" content="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def create_account(self, username, password, role="user", email=""):
        return create_user(
            application.DB_PATH,
            username,
            generate_password_hash(password),
            role,
            email,
        )

    def sign_in(self, client, username, password, role):
        token = self.csrf_token(client)
        return client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": username,
                "password": password,
                "role": role,
            },
        )

    def test_registration_creates_only_user_accounts_with_hashed_passwords(self):
        token = self.csrf_token(self.client, "/register")
        response = self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "analyst_one",
                "password": "correct-horse-battery",
                "email": "analyst@example.test",
            },
        )
        self.assertEqual(response.status_code, 302)
        user = get_user_by_username(application.DB_PATH, "analyst_one")
        self.assertEqual(user["role"], "user")
        self.assertEqual(user["email"], "analyst@example.test")
        self.assertNotEqual(user["password_hash"], "correct-horse-battery")

    def test_login_requires_the_selected_account_role(self):
        self.create_account("reviewer", "very-long-test-password", "user")
        response = self.sign_in(
            self.client, "reviewer", "very-long-test-password", "admin"
        )
        self.assertEqual(response.status_code, 401)
        response = self.sign_in(
            self.client, "reviewer", "very-long-test-password", "user"
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_profile_is_available_for_users_and_admins_and_links_from_header(self):
        for role, username in (("user", "profile_user"), ("admin", "profile_admin")):
            self.create_account(username, "profile-password-long", role, f"{username}@example.test")
            client = application.app.test_client()
            self.assertEqual(self.sign_in(client, username, "profile-password-long", role).status_code, 302)
            dashboard = client.get("/")
            self.assertIn(b'href="/profile"', dashboard.data)
            self.assertIn(b"Profile settings", dashboard.data)
            self.assertIn(b"Security &amp; MFA", dashboard.data)
            self.assertIn(username.encode(), dashboard.data)
            profile_response = client.get("/profile")
            self.assertEqual(profile_response.status_code, 200)
            self.assertIn(b"Account information", profile_response.data)
            self.assertIn(b"Change password", profile_response.data)
            self.assertIn(b'aria-label="Profile settings"', profile_response.data)
            self.assertIn(b'href="#account-settings"', profile_response.data)
            self.assertIn(b'href="#password-settings"', profile_response.data)
            self.assertIn(b'href="/settings/security"', profile_response.data)
            self.assertIn(
                br'pattern="[a-zA-Z0-9_\x2D]{3,32}"',
                profile_response.data,
            )
            self.assertIn(role.title().encode(), profile_response.data)

    def test_profile_updates_username_and_recovery_email_in_database(self):
        user_id = self.create_account(
            "editable_user", "editable-password-long", email="before@example.test"
        )
        self.sign_in(self.client, "editable_user", "editable-password-long", "user")
        response = self.client.post(
            "/profile",
            data={
                "csrf_token": self.csrf_token(self.client, "/profile"),
                "action": "update_profile",
                "username": "renamed_user",
                "email": "after@example.test",
                "current_password": "editable-password-long",
            },
        )
        self.assertEqual(response.status_code, 302)
        user = get_user_by_id(application.DB_PATH, user_id)
        self.assertEqual(user["username"], "renamed_user")
        self.assertEqual(user["email"], "after@example.test")
        self.assertEqual(user["role"], "user")
        self.assertEqual(self.client.get("/profile").status_code, 200)

    def test_profile_rejects_wrong_current_password_and_duplicate_email(self):
        self.create_account("first_profile", "first-password-long", email="first@example.test")
        self.create_account("second_profile", "second-password-long", email="second@example.test")
        self.sign_in(self.client, "first_profile", "first-password-long", "user")
        token = self.csrf_token(self.client, "/profile")

        response = self.client.post(
            "/profile",
            data={
                "csrf_token": token,
                "action": "update_profile",
                "username": "first_profile",
                "email": "first@example.test",
                "current_password": "incorrect-password",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"current password is incorrect", response.data)
        response = self.client.post(
            "/profile",
            data={
                "csrf_token": token,
                "action": "update_profile",
                "username": "first_profile",
                "email": "second@example.test",
                "current_password": "first-password-long",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"already in use", response.data)
        self.assertEqual(get_user_by_username(application.DB_PATH, "first_profile")["email"], "first@example.test")

    def test_profile_password_change_keeps_current_session_and_invalidates_others(self):
        user_id = self.create_account("password_user", "old-profile-password")
        active_client = application.app.test_client()
        other_client = application.app.test_client()
        self.sign_in(active_client, "password_user", "old-profile-password", "user")
        self.sign_in(other_client, "password_user", "old-profile-password", "user")
        response = active_client.post(
            "/profile",
            data={
                "csrf_token": self.csrf_token(active_client, "/profile"),
                "action": "change_password",
                "current_password": "old-profile-password",
                "password": "new-profile-password",
                "password_confirm": "new-profile-password",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(active_client.get("/profile").status_code, 200)
        self.assertEqual(other_client.get("/").status_code, 302)
        self.assertEqual(get_user_by_id(application.DB_PATH, user_id)["session_version"], 1)

        login_response = self.sign_in(self.client, "password_user", "new-profile-password", "user")
        self.assertEqual(login_response.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_empty_investigation_register_links_to_persistent_case_creation(self):
        owner_id = self.create_account("empty_owner", "empty-password-long")
        self.sign_in(self.client, "empty_owner", "empty-password-long", "user")
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b'<a class="empty" href="#new-case"', dashboard.data)
        self.assertIn(b"Create your first case", dashboard.data)

        response = self.client.post(
            "/cases",
            data={
                "csrf_token": self.csrf_token(self.client, "/"),
                "title": "Clickable empty state case",
                "description": "Created from the dashboard prompt",
            },
        )
        self.assertEqual(response.status_code, 302)
        case_id = int(response.location.rsplit("/", 1)[1])
        case = get_case(application.DB_PATH, case_id)
        self.assertEqual(case["title"], "Clickable empty state case")
        self.assertEqual(case["owner_id"], owner_id)
        self.assertEqual(
            self.client.get("/").status_code,
            200,
        )
        self.assertNotIn(b'class="empty" href="#new-case"', self.client.get("/").data)

    def test_users_only_see_their_cases_and_admins_see_all_cases(self):
        owner_id = self.create_account("case_owner", "very-long-test-password")
        admin_id = self.create_account("root_admin", "another-long-test-password", "admin")
        owner_client = application.app.test_client()
        self.assertEqual(
            self.sign_in(owner_client, "case_owner", "very-long-test-password", "user").status_code,
            302,
        )
        create_response = owner_client.post(
            "/cases",
            data={
                "csrf_token": self.csrf_token(owner_client, "/"),
                "title": "Private investigation",
                "description": "Owner-only case",
            },
        )
        self.assertEqual(create_response.status_code, 302)
        case_id = int(create_response.location.rsplit("/", 1)[1])
        self.assertEqual(owner_client.get(f"/cases/{case_id}").status_code, 200)

        other_client = application.app.test_client()
        self.create_account("other_user", "other-long-test-password")
        self.assertEqual(
            self.sign_in(other_client, "other_user", "other-long-test-password", "user").status_code,
            302,
        )
        self.assertEqual(other_client.get("/").status_code, 200)
        self.assertEqual(other_client.get(f"/cases/{case_id}").status_code, 404)
        self.assertNotIn(b"Private investigation", other_client.get("/").data)

        admin_client = application.app.test_client()
        self.assertEqual(
            self.sign_in(admin_client, "root_admin", "another-long-test-password", "admin").status_code,
            302,
        )
        self.assertIn(b"Private investigation", admin_client.get("/").data)
        self.assertIn(b"Owner", admin_client.get("/").data)
        self.assertIn(b"case_owner", admin_client.get("/").data)
        self.assertEqual(get_case(application.DB_PATH, case_id)["owner_id"], owner_id)
        self.assertGreater(admin_id, 0)

    def test_admin_pages_are_forbidden_to_regular_users(self):
        self.create_account("ordinary_user", "ordinary-password-long")
        self.sign_in(
            self.client, "ordinary_user", "ordinary-password-long", "user"
        )
        self.assertEqual(self.client.get("/admin/accounts").status_code, 403)
        self.assertEqual(self.client.get("/admin/audit-integrity").status_code, 403)

    def test_storage_quota_rejects_upload_without_persisting_evidence(self):
        user_id = self.create_account("quota_user", "quota-password-long")
        case_id = application.create_case(
            application.DB_PATH, "Quota test", "", user_id
        )
        self.sign_in(self.client, "quota_user", "quota-password-long", "user")
        upload_dir = Path(self.temp_dir.name) / "uploads"
        upload_dir.mkdir()
        with patch.object(application, "UPLOAD_DIR", str(upload_dir)), patch.object(
            application, "MAX_USER_STORAGE_BYTES", 3
        ):
            token = self.csrf_token(self.client, f"/cases/{case_id}")
            response = self.client.post(
                f"/cases/{case_id}/upload",
                data={
                    "csrf_token": token,
                    "evidence": (io.BytesIO(b"four"), "oversized.txt"),
                },
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 302)
        with connect(application.DB_PATH) as conn:
            evidence_count = conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id=?", (case_id,)
            ).fetchone()[0]
        self.assertEqual(evidence_count, 0)
        self.assertEqual(list(upload_dir.iterdir()), [])

    def test_evidence_register_displays_persisted_integrity_and_analysis_status(self):
        user_id = self.create_account("evidence_user", "evidence-password-long")
        case_id = application.create_case(
            application.DB_PATH, "Evidence status test", "", user_id
        )
        self.sign_in(self.client, "evidence_user", "evidence-password-long", "user")
        upload_dir = Path(self.temp_dir.name) / "evidence-uploads"
        upload_dir.mkdir()
        csv_data = (
            "timestamp,event_type,source_ip,status\n"
            "2025-01-01T12:00:00Z,login,192.0.2.10,success\n"
        )
        with patch.object(application, "UPLOAD_DIR", str(upload_dir)):
            token = self.csrf_token(self.client, f"/cases/{case_id}")
            response = self.client.post(
                f"/cases/{case_id}/upload",
                data={
                    "csrf_token": token,
                    "evidence": (io.BytesIO(csv_data.encode()), "access.log.csv"),
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 302)

            case_page = self.client.get(f"/cases/{case_id}")
            self.assertEqual(case_page.status_code, 200)
            self.assertIn(b"access.log.csv", case_page.data)
            self.assertIn(b"SHA-256", case_page.data)
            self.assertIn(b"Hash recorded", case_page.data)
            self.assertIn(b"Not analyzed", case_page.data)

            token = self.csrf_token(self.client, f"/cases/{case_id}")
            response = self.client.post(
                f"/cases/{case_id}/verify", data={"csrf_token": token}
            )
            self.assertEqual(response.status_code, 302)
            self.assertIn(b"Verified", self.client.get(f"/cases/{case_id}").data)

            token = self.csrf_token(self.client, f"/cases/{case_id}")
            response = self.client.post(
                f"/cases/{case_id}/analyze", data={"csrf_token": token}
            )
            self.assertEqual(response.status_code, 302)
            analyzed_page = self.client.get(f"/cases/{case_id}")
            self.assertEqual(analyzed_page.status_code, 200)
            self.assertIn(b"Analyzed", analyzed_page.data)
            self.assertIn(b"Search exports", analyzed_page.data)
            self.assertIn(b"PDF investigation report", analyzed_page.data)

            report_dir = os.path.join(self.temp_dir.name, "reports")
            os.makedirs(report_dir)
            with patch.object(application, "REPORT_DIR", report_dir):
                pdf_response = self.client.get(f"/cases/{case_id}/report")
                csv_response = self.client.get(f"/cases/{case_id}/report.csv")
            self.assertEqual(pdf_response.status_code, 200)
            pdf_data = pdf_response.data
            pdf_response.close()
            self.assertTrue(pdf_data.startswith(b"%PDF-"))
            self.assertEqual(csv_response.status_code, 200)
            self.assertIn("text/csv", csv_response.content_type)

    def test_workspace_review_totals_are_scoped_and_exclude_reviewed_findings(self):
        owner_id = self.create_account("review_owner", "review-password-long")
        other_id = self.create_account("review_other", "other-review-password-long")
        owner_case = application.create_case(
            application.DB_PATH, "Owner review case", "", owner_id
        )
        other_case = application.create_case(
            application.DB_PATH, "Other review case", "", other_id
        )
        owner_events = add_events(
            application.DB_PATH,
            owner_case,
            [
                {"severity": "high", "summary": "High finding"},
                {"severity": "medium", "summary": "Medium finding"},
                {"severity": "low", "summary": "Low event"},
            ],
        )
        add_events(
            application.DB_PATH,
            other_case,
            [
                {"severity": "high", "summary": "Other high finding"},
                {"severity": "medium", "summary": "Other medium finding"},
            ],
        )
        self.assertTrue(
            save_finding_feedback(
                application.DB_PATH,
                owner_case,
                owner_events[0],
                "true_positive",
                "",
                "review_owner",
            )
        )

        self.assertEqual(
            get_workspace_review_summary(application.DB_PATH, owner_id),
            {"high_findings": 1, "pending_reviews": 1},
        )
        self.assertEqual(
            get_workspace_review_summary(application.DB_PATH),
            {"high_findings": 2, "pending_reviews": 3},
        )

    def test_image_job_recovery_retry_and_cancellation(self):
        user_id = self.create_account("job_user", "job-password-long")
        case_id = application.create_case(
            application.DB_PATH, "Job test", "", user_id
        )
        image_id = "queued-image"
        add_disk_image(
            application.DB_PATH, image_id, case_id, "disk.img", "images",
            "disk.img", "raw", 10, "0" * 64, [],
        )
        job_id = enqueue_background_job(
            application.DB_PATH, "image_analysis", case_id, image_id, "job_user"
        )
        self.assertTrue(claim_background_job(application.DB_PATH, job_id))
        self.assertFalse(claim_background_job(application.DB_PATH, job_id))

        recovered = recover_background_jobs(application.DB_PATH)
        self.assertEqual([job["id"] for job in recovered], [job_id])
        self.assertEqual(get_background_job(application.DB_PATH, job_id)["status"], "queued")
        self.assertEqual(get_disk_image(application.DB_PATH, image_id)["analysis_status"], "queued")

        self.assertTrue(claim_background_job(application.DB_PATH, job_id))
        update_background_job(application.DB_PATH, job_id, "failed", "worker stopped")
        retried = retry_background_job(
            application.DB_PATH, job_id, case_id, "job_user"
        )
        self.assertEqual(retried["status"], "queued")
        self.assertEqual(retried["retry_count"], 1)
        self.assertTrue(cancel_background_job(application.DB_PATH, job_id))
        self.assertFalse(cancel_background_job(application.DB_PATH, job_id))
        self.assertEqual(get_background_job(application.DB_PATH, job_id)["status"], "cancelled")

    def test_environment_bootstrap_creates_the_first_administrator(self):
        with patch.dict(
            os.environ,
            {
                "AI_DFIR_ADMIN_USERNAME": "bootstrap_admin",
                "AI_DFIR_ADMIN_PASSWORD": "bootstrap-password-long",
            },
        ):
            application._bootstrap_admin()
        admin = get_user_by_username(application.DB_PATH, "bootstrap_admin")
        self.assertEqual(admin["role"], "admin")
        self.assertNotEqual(admin["password_hash"], "bootstrap-password-long")

    def test_case_audit_chain_detects_record_changes(self):
        owner_id = self.create_account("audit_user", "audit-password-long")
        case_id = application.create_case(
            application.DB_PATH, "Audit case", "Test hash chaining", owner_id
        )
        add_audit(application.DB_PATH, case_id, "CREATED", "initial", "audit_user")
        add_audit(application.DB_PATH, case_id, "UPDATED", "details", "audit_user")
        self.assertTrue(verify_audit_chain(application.DB_PATH)["valid"])
        with connect(application.DB_PATH) as conn:
            conn.execute("UPDATE audit SET details='tampered' WHERE action='CREATED'")
        self.assertFalse(verify_audit_chain(application.DB_PATH)["valid"])

    def test_mutations_require_a_csrf_token(self):
        self.create_account("csrf_user", "csrf-long-test-password")
        self.assertEqual(
            self.sign_in(
                self.client, "csrf_user", "csrf-long-test-password", "user"
            ).status_code,
            302,
        )
        response = self.client.post("/cases", data={"title": "Missing token"})
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            "/cases", data={"csrf_token": "🌐", "title": "Malformed token"}
        )
        self.assertEqual(response.status_code, 400)

    def test_unauthenticated_case_api_requires_login(self):
        response = self.client.post("/api/cases/1/notes", json={"note": "test"})
        self.assertEqual(response.status_code, 401)

    def test_login_attempts_are_throttled_after_five_failures(self):
        self.create_account("throttle_user", "valid-test-password-long")
        token = self.csrf_token(self.client)
        for _ in range(5):
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": token,
                    "username": "throttle_user",
                    "password": "wrong-password",
                    "role": "user",
                },
            )
            self.assertEqual(response.status_code, 401)
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "throttle_user",
                "password": "valid-test-password-long",
                "role": "user",
            },
        )
        self.assertEqual(response.status_code, 429)

    def test_totp_enrollment_and_login_challenge(self):
        self.create_account("mfa_user", "valid-mfa-password-long", email="mfa@example.test")
        self.assertEqual(
            self.sign_in(
                self.client, "mfa_user", "valid-mfa-password-long", "user"
            ).status_code,
            302,
        )
        token = self.csrf_token(self.client, "/settings/security")
        response = self.client.post(
            "/settings/security",
            data={"csrf_token": token, "action": "begin_mfa"},
        )
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'readonly value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        secret = match.group(1).decode()
        response = self.client.post(
            "/settings/security",
            data={
                "csrf_token": token,
                "action": "enable_mfa",
                "mfa_code": pyotp.TOTP(secret).now(),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Save these recovery codes now", response.data)
        self.assertTrue(get_user_by_username(application.DB_PATH, "mfa_user")["totp_enabled"])

        self.client.post(
            "/logout",
            data={"csrf_token": self.csrf_token(self.client, "/settings/security")},
        )
        self.assertEqual(
            self.sign_in(
                self.client, "mfa_user", "valid-mfa-password-long", "user"
            ).status_code,
            302,
        )
        self.assertIn(b"authenticator code", self.client.get("/login").data.lower())
        totp = pyotp.TOTP(secret)
        next_counter = totp.timecode(application.datetime.now(application.timezone.utc)) + 1
        code = totp.at(next_counter * totp.interval + 1)
        response = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(self.client),
                "mfa_code": code,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_password_reset_is_generic_and_one_time(self):
        self.create_account("reset_user", "old-password-long", email="reset@example.test")
        sent = []
        with patch.object(application, "_email_configured", return_value=True), patch.object(
            application, "_send_email", side_effect=lambda recipient, subject, body: sent.append(body)
        ):
            response = self.client.post(
                "/password/forgot",
                data={
                    "csrf_token": self.csrf_token(self.client, "/password/forgot"),
                    "email": "reset@example.test",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertIn(
            "If the account can receive recovery email",
            self.client.get(response.location).get_data(as_text=True),
        )
        match = re.search(r"http://localhost/password/reset/([A-Za-z0-9._-]+)", sent[0])
        self.assertIsNotNone(match)
        reset_url = f"/password/reset/{match.group(1)}"
        reset_csrf = self.csrf_token(self.client, reset_url)
        response = self.client.post(
            reset_url,
            data={
                "csrf_token": reset_csrf,
                "password": "new-password-is-long",
            },
        )
        self.assertEqual(response.status_code, 302)
        response = self.client.post(
            reset_url,
            data={
                "csrf_token": reset_csrf,
                "password": "another-password-long",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            self.sign_in(self.client, "reset_user", "new-password-is-long", "user").status_code,
            302,
        )


if __name__ == "__main__":
    unittest.main()
