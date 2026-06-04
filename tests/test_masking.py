"""Testes para PII masker."""

from governance.masking.masker import MaskingPattern, PIIMasker


class TestPIIMasker:
    def test_email_masked(self) -> None:
        m = PIIMasker.with_patterns(MaskingPattern.EMAIL)
        result = m.mask_string("contact: user@example.com today")
        assert "user@example.com" not in result
        assert "[EMAIL]" in result

    def test_cpf_masked(self) -> None:
        m = PIIMasker.with_patterns(MaskingPattern.CPF)
        result = m.mask_string("CPF: 123.456.789-00")
        assert "123.456.789-00" not in result

    def test_jwt_masked(self) -> None:
        m = PIIMasker.with_patterns(MaskingPattern.JWT_TOKEN)
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123"
        result = m.mask_string(token)
        assert "eyJ" not in result

    def test_dict_masked_recursively(self) -> None:
        m = PIIMasker.with_patterns(MaskingPattern.EMAIL)
        data = {"user": {"email": "foo@bar.com", "name": "Test"}}
        result = m.mask_details(data)
        assert result["user"]["email"] != "foo@bar.com"
        assert result["user"]["name"] == "Test"

    def test_non_pii_unchanged(self) -> None:
        m = PIIMasker.with_defaults()
        result = m.mask_string("SELECT COUNT(*) FROM orders WHERE status=active")
        assert result == "SELECT COUNT(*) FROM orders WHERE status=active"

    def test_custom_rule(self) -> None:
        m = PIIMasker()
        m.add_rule(r"\b\d{4}-\d{4}\b", "[ACCOUNT]", "account_number")
        result = m.mask_string("account 1234-5678 is active")
        assert "1234-5678" not in result
        assert "[ACCOUNT]" in result
