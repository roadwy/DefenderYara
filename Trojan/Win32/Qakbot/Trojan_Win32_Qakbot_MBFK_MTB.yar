
rule Trojan_Win32_Qakbot_MBFK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MBFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 61 69 72 6f 5f 61 70 70 65 6e 64 5f 70 61 74 68 } //01 00  kairo_append_path
		$a_01_1 = {6b 61 69 72 6f 5f 63 6c 6f 73 65 5f 70 61 74 68 } //01 00  kairo_close_path
		$a_01_2 = {6b 61 69 72 6f 5f 64 65 62 75 67 5f 72 65 73 65 74 5f 73 74 61 74 69 63 5f 64 61 74 61 } //01 00  kairo_debug_reset_static_data
		$a_01_3 = {6b 61 69 72 6f 5f 64 65 73 74 72 6f 79 } //01 00  kairo_destroy
		$a_01_4 = {6b 61 69 72 6f 5f 64 65 76 69 63 65 5f 67 65 74 5f 72 65 66 65 72 65 6e 63 65 5f 63 6f 75 6e 74 } //01 00  kairo_device_get_reference_count
		$a_01_5 = {6b 61 69 72 6f 5f 66 6f 6e 74 5f 6f 70 74 69 6f 6e 73 5f 67 65 74 5f 68 69 6e 74 5f 6d 65 74 72 69 63 73 } //01 00  kairo_font_options_get_hint_metrics
		$a_01_6 = {6b 61 69 72 6f 5f 66 6f 6e 74 5f 6f 70 74 69 6f 6e 73 5f 67 65 74 5f 73 75 62 70 69 78 65 6c 5f 6f 72 64 65 72 } //01 00  kairo_font_options_get_subpixel_order
		$a_01_7 = {6b 61 69 72 6f 5f 67 6c 79 70 68 5f 61 6c 6c 6f 63 61 74 65 } //01 00  kairo_glyph_allocate
		$a_01_8 = {6b 61 69 72 6f 5f 69 6d 61 67 65 5f 73 75 72 66 61 63 65 5f 63 72 65 61 74 65 5f 66 6f 72 5f 64 61 74 61 } //01 00  kairo_image_surface_create_for_data
		$a_01_9 = {6b 61 69 72 6f 5f 6d 61 74 72 69 78 5f 74 72 61 6e 73 66 6f 72 6d 5f 64 69 73 74 61 6e 63 65 } //01 00  kairo_matrix_transform_distance
		$a_01_10 = {6b 61 69 72 6f 5f 70 61 74 74 65 72 6e 5f 61 64 64 5f 63 6f 6c 6f 72 5f 73 74 6f 70 5f 72 67 62 61 } //01 00  kairo_pattern_add_color_stop_rgba
		$a_01_11 = {6b 61 69 72 6f 5f 70 64 66 5f 73 75 72 66 61 63 65 5f 72 65 73 74 72 69 63 74 5f 74 6f 5f 76 65 72 73 69 6f 6e } //01 00  kairo_pdf_surface_restrict_to_version
		$a_01_12 = {6b 61 69 72 6f 5f 72 65 67 69 6f 6e 5f 78 6f 72 } //01 00  kairo_region_xor
		$a_01_13 = {6b 61 69 72 6f 5f 78 6d 6c 5f 63 72 65 61 74 65 5f 66 6f 72 5f 73 74 72 65 61 6d } //01 00  kairo_xml_create_for_stream
		$a_01_14 = {6d 75 73 74 } //00 00  must
	condition:
		any of ($a_*)
 
}