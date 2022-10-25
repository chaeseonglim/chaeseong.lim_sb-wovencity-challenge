#ifdef __cplusplus
extern "C" {
#endif

struct tlv_iter {
    const struct img_hdr *hdr;
    const struct storage *stg;
    uint16_t tag;
    uint32_t len;
    uint32_t tlv_off;
    uint32_t tlv_end;
};

int tlv_go_begin(struct tlv_iter *it,const struct img_hdr *stg, const struct storage *fap);

int tlv_next_tag(struct tlv_iter *it, uint32_t *off,uint16_t *len, uint16_t *tag);
#ifdef __cplusplus
}
#endif