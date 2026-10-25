#include <stdbool.h>
#include <stdint.h>
#include <string.h>

bool tud_hid_n_ready(uint8_t instance);
bool tud_hid_n_report(uint8_t instance, uint8_t report_id, const void *report, uint16_t length);

#define FIDO2_HID_INSTANCE 3
#define FIDO2_REPORT_SIZE 64
#define FIDO2_QUEUE_DEPTH 8

static uint8_t rx_queue[FIDO2_QUEUE_DEPTH][FIDO2_REPORT_SIZE];
static volatile uint8_t rx_head;
static volatile uint8_t rx_tail;
static uint8_t tx_queue[FIDO2_QUEUE_DEPTH][FIDO2_REPORT_SIZE];
static volatile uint8_t tx_head;
static volatile uint8_t tx_tail;
static volatile bool tx_active;

static uint8_t queue_next(uint8_t index)
{
  return (uint8_t)((index + 1) % FIDO2_QUEUE_DEPTH);
}

void fido2_usb_receive_report(const uint8_t *report, uint16_t length)
{
  if (length != FIDO2_REPORT_SIZE) return;
  uint8_t next = queue_next(rx_head);
  if (next == rx_tail) return;
  memcpy(rx_queue[rx_head], report, FIDO2_REPORT_SIZE);
  rx_head = next;
}

bool fido2_usb_pop_report(uint8_t report[FIDO2_REPORT_SIZE])
{
  if (rx_tail == rx_head) return false;
  memcpy(report, rx_queue[rx_tail], FIDO2_REPORT_SIZE);
  rx_tail = queue_next(rx_tail);
  return true;
}

static void send_next(void)
{
  if (tx_active || tx_tail == tx_head || !tud_hid_n_ready(FIDO2_HID_INSTANCE)) return;
  tx_active = tud_hid_n_report(FIDO2_HID_INSTANCE, 0, tx_queue[tx_tail], FIDO2_REPORT_SIZE);
}

bool fido2_usb_push_report(const uint8_t report[FIDO2_REPORT_SIZE])
{
  uint8_t next = queue_next(tx_head);
  if (next == tx_tail) return false;
  memcpy(tx_queue[tx_head], report, FIDO2_REPORT_SIZE);
  tx_head = next;
  send_next();
  return true;
}

void fido2_usb_report_complete(void)
{
  if (tx_active) {
    tx_tail = queue_next(tx_tail);
    tx_active = false;
  }
  send_next();
}
