
rule Trojan_Win32_Qakbot_MH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 56 4c 8b be ?? ?? ?? ?? 8d 5a 01 89 5e 4c 88 0c 17 8b 4e 4c 8b 96 ?? ?? ?? ?? 8d 79 01 89 7e 4c 88 24 0a 8b 4e 4c 8b 96 ?? ?? ?? ?? 8d 79 01 89 7e 4c 88 04 0a 8b 86 18 01 00 00 33 86 } //10
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //5 DllRegisterServer
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}
rule Trojan_Win32_Qakbot_MH_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {78 61 69 72 6f 5f 61 70 70 65 6e 64 5f 70 61 74 68 } //1 xairo_append_path
		$a_01_1 = {78 61 69 72 6f 5f 61 72 63 5f 6e 65 67 61 74 69 76 65 } //1 xairo_arc_negative
		$a_01_2 = {78 61 69 72 6f 5f 63 6c 69 70 5f 70 72 65 73 65 72 76 65 } //1 xairo_clip_preserve
		$a_01_3 = {78 61 69 72 6f 5f 63 6f 70 79 5f 70 61 74 68 5f 66 6c 61 74 } //1 xairo_copy_path_flat
		$a_01_4 = {78 61 69 72 6f 5f 64 65 62 75 67 5f 72 65 73 65 74 5f 73 74 61 74 69 63 5f 64 61 74 61 } //1 xairo_debug_reset_static_data
		$a_01_5 = {78 61 69 72 6f 5f 64 65 76 69 63 65 5f 67 65 74 5f 72 65 66 65 72 65 6e 63 65 5f 63 6f 75 6e 74 } //1 xairo_device_get_reference_count
		$a_01_6 = {78 61 69 72 6f 5f 64 65 76 69 63 65 5f 67 65 74 5f 75 73 65 72 5f 64 61 74 61 } //1 xairo_device_get_user_data
		$a_01_7 = {78 61 69 72 6f 5f 64 65 76 69 63 65 5f 74 6f 5f 75 73 65 72 5f 64 69 73 74 61 6e 63 65 } //1 xairo_device_to_user_distance
		$a_01_8 = {78 61 69 72 6f 5f 66 74 5f 66 6f 6e 74 5f 66 61 63 65 5f 63 72 65 61 74 65 5f 66 6f 72 5f 70 61 74 74 65 72 6e } //1 xairo_ft_font_face_create_for_pattern
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}