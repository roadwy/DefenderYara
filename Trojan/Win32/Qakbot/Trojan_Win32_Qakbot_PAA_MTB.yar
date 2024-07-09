
rule Trojan_Win32_Qakbot_PAA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {89 55 fc 8b 45 fc c1 f8 02 89 45 fc 8b 55 fc 2b 55 10 03 55 fc 8b 4d fc d3 fa 8b 4d fc d3 fa 8b 0d 24 fe 05 10 0f af 0d 8c fd 05 10 a1 d0 fd 05 10 d3 f8 8b 4d 14 d3 e0 33 d0 8b 45 fc 2b 45 08 8b 4d fc 03 4d 18 03 4d 20 03 4d 08 d3 e0 8b 4d fc d3 e0 } //1
		$a_03_1 = {8b 0d 28 fe 05 10 d3 e2 33 c2 8b 55 fc 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 0d 44 fe 05 10 d3 e2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_PAA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 76 5f 65 6e 63 72 79 70 74 69 6f 6e 5f 69 6e 69 74 5f 69 6e 66 6f 5f 61 64 64 5f 73 69 64 65 5f 64 61 74 61 } //1 Iv_encryption_init_info_add_side_data
		$a_01_1 = {49 76 5f 66 72 61 6d 65 5f 73 65 74 5f 62 65 73 74 5f 65 66 66 6f 72 74 5f 74 69 6d 65 73 74 61 6d 70 } //1 Iv_frame_set_best_effort_timestamp
		$a_01_2 = {49 76 5f 78 74 65 61 5f 6c 65 5f 63 72 79 70 74 } //1 Iv_xtea_le_crypt
		$a_01_3 = {49 76 70 72 69 76 5f 73 6c 69 63 65 74 68 72 65 61 64 5f 63 72 65 61 74 65 } //1 Ivpriv_slicethread_create
		$a_01_4 = {4d 6f 74 64 } //1 Motd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}