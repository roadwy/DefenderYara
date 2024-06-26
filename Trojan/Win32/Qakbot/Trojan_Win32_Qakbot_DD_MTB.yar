
rule Trojan_Win32_Qakbot_DD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 1c 83 44 24 10 04 05 64 b2 00 01 a3 90 01 04 89 06 8d 04 0a 8b 0d 90 01 04 03 c7 8b 35 90 01 04 81 c1 8f 27 01 00 8d 04 42 03 c8 ff 4c 24 14 90 00 } //01 00 
		$a_03_1 = {0f af cf 89 3d 90 01 04 69 f9 bc 6a 00 00 0f b6 cb 81 c6 f8 39 0b 01 8a 1d 90 01 04 66 2b c8 66 2b ca 89 35 90 01 04 0f b7 d1 8b 4c 24 10 89 54 24 0c 89 31 90 00 } //01 00 
		$a_03_2 = {0f b7 55 fc a1 90 01 04 8d 4c 02 a9 03 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 81 c2 d8 1f 0b 01 89 15 90 01 04 a1 90 01 04 03 45 f8 8b 0d 90 01 04 89 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_DD_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 64 5f 72 65 61 64 5f 6d 6f 62 6a } //01 00  jd_read_mobj
		$a_01_1 = {6a 64 5f 72 65 61 64 5f 6d 70 6c 73 } //01 00  jd_read_mpls
		$a_01_2 = {6a 64 5f 72 65 61 64 5f 73 6b 69 70 5f 73 74 69 6c 6c } //01 00  jd_read_skip_still
		$a_01_3 = {6a 64 5f 72 65 67 69 73 74 65 72 5f 61 72 67 62 5f 6f 76 65 72 6c 61 79 5f 70 72 6f 63 } //01 00  jd_register_argb_overlay_proc
		$a_01_4 = {6a 64 5f 72 65 67 69 73 74 65 72 5f 6f 76 65 72 6c 61 79 5f 70 72 6f 63 } //01 00  jd_register_overlay_proc
		$a_01_5 = {6a 64 5f 73 65 61 6d 6c 65 73 73 5f 61 6e 67 6c 65 5f 63 68 61 6e 67 65 } //01 00  jd_seamless_angle_change
		$a_01_6 = {6a 64 5f 73 65 74 5f 70 6c 61 79 65 72 5f 73 65 74 74 69 6e 67 5f 73 74 72 } //01 00  jd_set_player_setting_str
		$a_01_7 = {6a 64 5f 73 74 61 72 74 5f 62 64 6a } //01 00  jd_start_bdj
		$a_01_8 = {6a 64 5f 74 65 6c 6c 5f 74 69 6d 65 } //01 00  jd_tell_time
		$a_01_9 = {6d 65 6e 75 } //00 00  menu
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_DD_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.DD!MTB,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 0b 00 00 05 00 "
		
	strings :
		$a_01_0 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } //01 00  DrawThemeIcon
		$a_01_1 = {61 6e 61 6c 6c 65 72 67 69 63 } //01 00  anallergic
		$a_01_2 = {61 70 6e 65 75 73 74 69 63 } //01 00  apneustic
		$a_01_3 = {65 6c 79 74 72 69 6e } //01 00  elytrin
		$a_01_4 = {68 6f 6d 65 63 72 6f 66 74 69 6e 67 } //01 00  homecrofting
		$a_01_5 = {6c 6f 6e 67 77 61 79 } //01 00  longway
		$a_01_6 = {6f 6d 6e 69 63 6f 72 70 6f 72 65 61 6c } //01 00  omnicorporeal
		$a_01_7 = {6f 6e 69 73 63 69 66 6f 72 6d } //01 00  onisciform
		$a_01_8 = {70 72 69 73 63 61 6e } //01 00  priscan
		$a_01_9 = {70 79 72 65 6e 6f 70 65 7a 69 7a 61 } //01 00  pyrenopeziza
		$a_01_10 = {75 6e 77 61 6b 65 6e 65 64 } //00 00  unwakened
	condition:
		any of ($a_*)
 
}