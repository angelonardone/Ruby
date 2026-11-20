#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../jade_assert.h"
#include "../seed_split.h"
#include "../ui.h"

// Ruby: screens of the Wallet Backup / Time Encrypted Vault split of the seed (see seed_split.h)

#define SEED_SPLIT_HELP_URL "distributedcryptography.com/ruby/backup"

// The contact's key as the wallet shows it: the first 10 and the last 8 hex characters ("02a1b2c3d4..e5f6a7b8"),
// so a key swapped on the computer is noticed when it is compared with the contact's key in the wallet.
static void seed_split_key_line(const uint8_t* pubkey, char* line, const size_t line_len)
{
    static const char hex[] = "0123456789abcdef";
    JADE_ASSERT(line_len >= 21);
    size_t pos = 0;
    for (size_t i = 0; i < 5; ++i) {
        line[pos++] = hex[pubkey[i] >> 4];
        line[pos++] = hex[pubkey[i] & 0x0f];
    }
    line[pos++] = '.';
    line[pos++] = '.';
    for (size_t i = EC_PUBLIC_KEY_LEN - 4; i < EC_PUBLIC_KEY_LEN; ++i) {
        line[pos++] = hex[pubkey[i] >> 4];
        line[pos++] = hex[pubkey[i] & 0x0f];
    }
    line[pos] = '\0';
}

bool show_seed_split_activity(const bool vault, const size_t threshold, const size_t total_shares,
    const seed_split_contact_t* contacts, const size_t num_contacts)
{
    JADE_ASSERT(contacts);
    JADE_ASSERT(num_contacts);

    const char* title = vault ? "Time Vault" : "Wallet Backup";
    char shares_line[32];
    int ret = snprintf(shares_line, sizeof(shares_line), "%u of %u shares", (unsigned)threshold, (unsigned)total_shares);
    JADE_ASSERT(ret > 0 && ret < sizeof(shares_line));
    char contacts_line[32];
    ret = snprintf(contacts_line, sizeof(contacts_line), "among %u contact%s", (unsigned)num_contacts,
        num_contacts == 1 ? "" : "s");
    JADE_ASSERT(ret > 0 && ret < sizeof(contacts_line));

    const char* summary[] = { vault ? "Split the vault seed" : "Split the wallet seed", shares_line, contacts_line };
    if (!await_yesno_activity(title, summary, 3, false, SEED_SPLIT_HELP_URL)) {
        return false;
    }

    for (size_t i = 0; i < num_contacts; ++i) {
        const seed_split_contact_t* const contact = &contacts[i];
        char contact_title[24];
        ret = snprintf(contact_title, sizeof(contact_title), "Contact %u of %u", (unsigned)(i + 1), (unsigned)num_contacts);
        JADE_ASSERT(ret > 0 && ret < sizeof(contact_title));
        char num_line[24];
        ret = snprintf(num_line, sizeof(num_line), "%u share%s", (unsigned)contact->num_shares,
            contact->num_shares == 1 ? "" : "s");
        JADE_ASSERT(ret > 0 && ret < sizeof(num_line));
        char key_line[24];
        seed_split_key_line(contact->pubkey, key_line, sizeof(key_line));

        const char* message[] = { contact->name, num_line, key_line };
        if (!await_yesno_activity(contact_title, message, 3, false, SEED_SPLIT_HELP_URL)) {
            return false;
        }
    }
    return true;
}
#endif // AMALGAMATED_BUILD
