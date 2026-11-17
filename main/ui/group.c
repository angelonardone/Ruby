#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../group.h"
#include "../jade_assert.h"
#include "../storage.h"
#include "../ui.h"

// Ruby: screens of the DistributedCryptography Taproot group registrations (see group.h)

#define GROUP_HELP_URL "distributedcryptography.com/ruby/groups"

gui_activity_t* make_display_address_activities(const char* title, bool show_one_screen_tick, const char* address,
    bool default_selection, gui_activity_t** actaddr2);

// "Delegated 2 of 3" / "Multi Signature 2 of 3", and the role of this Ruby
static void group_summary_lines(const group_data_t* group, char* kind, const size_t kind_len, const char** role)
{
    const int ret = snprintf(kind, kind_len, "%s %u of %u", group_type_name(group->type), group->threshold,
        group->num_signers);
    JADE_ASSERT(ret > 0 && ret < kind_len);
    *role = group->we_are_owner                        ? "You are the owner"
        : group_type_has_owner(group->type) ? "You are a member"
                                              : "You are a signer";
}

// The first receiving address of the group, to compare with the one the wallet app shows
static bool show_group_address_activity(const char* address)
{
    const bool show_tick = true;
    const bool default_selection = false;
    gui_activity_t* act_addr2 = NULL;
    gui_activity_t* const act_addr1
        = make_display_address_activities("Group Address 1", show_tick, address, default_selection, &act_addr2);
    gui_activity_t* act = act_addr1;
    while (true) {
        gui_set_current_activity(act);
        switch (gui_activity_wait_button(act, BTN_ADDRESS_ACCEPT)) {
        case BTN_BACK:
            act = act_addr1;
            break;
        case BTN_ADDRESS_NEXT:
            act = act_addr2;
            break;
        case BTN_ADDRESS_REJECT:
            return false;
        case BTN_ADDRESS_ACCEPT:
            return true;
        }
    }
}

// Registration: the group summary, then its first address; true if both are accepted
bool show_register_group_activity(const group_data_t* group, const char* address0, const bool overwriting)
{
    JADE_ASSERT(group);
    JADE_ASSERT(address0);

    char kind[48];
    const char* role = NULL;
    group_summary_lines(group, kind, sizeof(kind), &role);

    const char* message[] = { group->label, kind, role, overwriting ? "Replaces the saved one" : NULL };
    const size_t message_size = overwriting ? 4 : 3;
    while (true) {
        if (!await_yesno_activity("Register Group", message, message_size, false, GROUP_HELP_URL)) {
            return false;
        }
        if (show_group_address_activity(address0)) {
            return true;
        }
        // Address rejected: back to the summary, where the registration can be declined
    }
}

#define UPDATE_GROUP_CAROUSEL(i)                                                                                       \
    do {                                                                                                               \
        if (i < num_groups) {                                                                                          \
            gui_update_text(label, "Group");                                                                           \
            gui_update_text(groupname, labels[i]);                                                                     \
        } else {                                                                                                       \
            gui_update_text(label, "");                                                                                \
            gui_update_text(groupname, "[Cancel]");                                                                    \
        }                                                                                                              \
    } while (false)

// Pick one of the registered groups (by its label); false if cancelled
bool select_registered_group(const char* const* labels, const size_t num_groups, size_t* selected_out)
{
    JADE_ASSERT(labels);
    JADE_ASSERT(num_groups);
    JADE_ASSERT(selected_out);

    size_t selected = 0;
    gui_view_node_t* label = NULL;
    gui_view_node_t* groupname = NULL;
    gui_activity_t* const act = make_carousel_activity("View Group", &label, &groupname);
    UPDATE_GROUP_CAROUSEL(0);
    gui_set_current_activity(act);

    const size_t limit = num_groups + 1;
    int32_t ev_id;
    bool done = false;
    while (!done) {
        UPDATE_GROUP_CAROUSEL(selected);
        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                selected = (selected + limit - 1) % limit;
            } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                selected = (selected + 1) % limit;
            } else if (ev_id == gui_get_click_event()) {
                done = true;
            }
        }
    }
    if (selected >= num_groups) {
        return false;
    }
    *selected_out = selected;
    return true;
}

// A registered group: its summary and first address; true if the user asks to delete it
bool show_view_group_activity(const group_data_t* group, const char* address0)
{
    JADE_ASSERT(group);

    char kind[48];
    const char* role = NULL;
    group_summary_lines(group, kind, sizeof(kind), &role);

    if (address0) {
        const char* message[] = { group->label, kind, role };
        if (await_continueback_activity("Registered Group", message, 3, true, GROUP_HELP_URL)) {
            show_group_address_activity(address0);
        }
    }
    const char* question[] = { group->label, "Delete this group", "from Ruby?" };
    return await_yesno_activity_critical("Delete Group", question, 3, false, GROUP_HELP_URL);
}
#endif // AMALGAMATED_BUILD
