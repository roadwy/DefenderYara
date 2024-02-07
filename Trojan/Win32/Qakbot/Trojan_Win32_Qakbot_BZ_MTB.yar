
rule Trojan_Win32_Qakbot_BZ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 6e 67 6f 5f 66 63 5f 64 65 63 6f 64 65 72 5f 67 65 74 5f 67 6c 79 70 68 } //01 00  Hango_fc_decoder_get_glyph
		$a_01_1 = {48 61 6e 67 6f 5f 66 63 5f 66 6f 6e 74 5f 63 72 65 61 74 65 5f 62 61 73 65 5f 6d 65 74 72 69 63 73 5f 66 6f 72 5f 63 6f 6e 74 65 78 74 } //01 00  Hango_fc_font_create_base_metrics_for_context
		$a_01_2 = {48 61 6e 67 6f 5f 66 63 5f 66 6f 6e 74 5f 6b 65 72 6e 5f 67 6c 79 70 68 73 } //01 00  Hango_fc_font_kern_glyphs
		$a_01_3 = {48 61 6e 67 6f 5f 66 63 5f 66 6f 6e 74 5f 6b 65 79 5f 67 65 74 5f 63 6f 6e 74 65 78 74 5f 6b 65 79 } //01 00  Hango_fc_font_key_get_context_key
		$a_01_4 = {48 61 6e 67 6f 5f 66 63 5f 66 6f 6e 74 5f 75 6e 6c 6f 63 6b 5f 66 61 63 65 } //01 00  Hango_fc_font_unlock_face
		$a_01_5 = {48 61 6e 67 6f 5f 66 74 32 5f 66 6f 6e 74 5f 67 65 74 5f 6b 65 72 6e 69 6e 67 } //01 00  Hango_ft2_font_get_kerning
		$a_01_6 = {48 61 6e 67 6f 5f 6f 74 5f 72 75 6c 65 73 65 74 5f 70 6f 73 69 74 69 6f 6e } //01 00  Hango_ot_ruleset_position
		$a_01_7 = {48 61 6e 67 6f 5f 66 74 32 5f 72 65 6e 64 65 72 5f 74 72 61 6e 73 66 6f 72 6d 65 64 } //00 00  Hango_ft2_render_transformed
	condition:
		any of ($a_*)
 
}