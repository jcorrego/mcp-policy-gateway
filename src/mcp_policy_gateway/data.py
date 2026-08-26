from .models import Account, Case

# Deliberately synthetic fixtures. Do not replace these with customer data.
ACCOUNTS = {
    "acct_red": Account(
        account_id="acct_red",
        tenant_id="tenant_red",
        owner_name="Avery Example",
        email="avery@example.test",
        status="active",
        balance_cents=12_500,
    ),
    "acct_blue": Account(
        account_id="acct_blue",
        tenant_id="tenant_blue",
        owner_name="Blake Example",
        email="blake@example.test",
        status="active",
        balance_cents=8_900,
    ),
}

CASES = {
    "case_red_01": Case(
        case_id="case_red_01",
        tenant_id="tenant_red",
        account_id="acct_red",
        summary="Customer reports an unexpected duplicate charge.",
        status="open",
    ),
    "case_blue_01": Case(
        case_id="case_blue_01",
        tenant_id="tenant_blue",
        account_id="acct_blue",
        summary="Customer requests a payment-method update.",
        status="open",
    ),
}
