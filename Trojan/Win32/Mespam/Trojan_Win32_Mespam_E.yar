
rule Trojan_Win32_Mespam_E{
	meta:
		description = "Trojan:Win32/Mespam.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 5c 28 ff 30 1c 32 3b 44 24 20 75 02 33 c0 42 40 3b d1 72 ea } //1
		$a_00_1 = {53 4f 43 4b 45 54 32 2e 44 4c 4c } //1 SOCKET2.DLL
		$a_01_2 = {75 0f 8b 54 1e 24 89 55 c4 b9 01 00 00 00 89 4d e8 47 8b 55 c0 3b fa 7c cc eb 33 } //1
		$a_00_3 = {4d 00 7a 00 4e 00 61 00 6d 00 65 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}