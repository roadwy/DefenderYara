
rule Trojan_Win32_Plugx_F_dha{
	meta:
		description = "Trojan:Win32/Plugx.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f8 3b fe 74 76 6a 00 57 ff 15 ?? ?? ?? ?? 89 45 08 89 03 8d 45 e8 50 68 ?? ?? ?? ?? c7 45 e8 56 69 72 74 c7 45 ec 75 61 6c 41 c7 45 f0 6c 6c 6f 63 c6 45 f4 00 ff 15 } //1
		$a_01_1 = {c6 45 f8 e8 2b c6 83 e8 05 89 45 f9 8b 45 f8 89 06 8a 45 fc 88 46 04 33 c0 } //1
		$a_03_2 = {2b c1 50 57 51 e8 d0 00 00 00 8b 35 ?? ?? ?? ?? 8d 85 f4 fe ff ff 83 c4 0c 68 ?? ?? ?? ?? 50 ff d6 68 ?? ?? ?? ?? 8d 85 f4 fe ff ff 50 ff d6 8d 45 fc 50 8d 55 f8 8d 8d f4 fe ff ff e8 b7 fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}