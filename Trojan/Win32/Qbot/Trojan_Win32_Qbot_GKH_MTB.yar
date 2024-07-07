
rule Trojan_Win32_Qbot_GKH_MTB{
	meta:
		description = "Trojan:Win32/Qbot.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 61 69 72 6f 5f 70 64 66 5f 73 75 72 66 61 63 65 5f 63 72 65 61 74 65 5f 66 6f 72 5f 73 74 72 65 61 6d } //1 iairo_pdf_surface_create_for_stream
		$a_01_1 = {69 61 69 72 6f 5f 75 73 65 72 5f 66 6f 6e 74 5f 66 61 63 65 5f 67 65 74 5f 75 6e 69 63 6f 64 65 5f 74 6f 5f 67 6c 79 70 68 5f 66 75 6e 63 } //1 iairo_user_font_face_get_unicode_to_glyph_func
		$a_01_2 = {69 61 69 72 6f 5f 72 65 67 69 6f 6e 5f 78 6f 72 5f 72 65 63 74 61 6e 67 6c 65 } //1 iairo_region_xor_rectangle
		$a_01_3 = {69 61 69 72 6f 5f 72 61 73 74 65 72 5f 73 6f 75 72 63 65 5f 70 61 74 74 65 72 6e 5f 67 65 74 5f 73 6e 61 70 73 68 6f 74 } //1 iairo_raster_source_pattern_get_snapshot
		$a_01_4 = {69 61 69 72 6f 5f 69 6e 5f 63 6c 69 70 } //1 iairo_in_clip
		$a_01_5 = {68 4c 61 57 79 4d 73 73 51 73 59 6e 69 44 59 } //1 hLaWyMssQsYniDY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}