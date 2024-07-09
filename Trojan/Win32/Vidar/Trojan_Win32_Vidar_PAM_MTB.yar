
rule Trojan_Win32_Vidar_PAM_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8d 0c 3e 8a 04 02 8b 95 ?? ?? ?? ?? 32 04 0a 46 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_PAM_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.PAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 03 f9 d9 ca 66 03 d6 75 04 74 02 37 8c 66 2b d6 ac 0f ba e1 75 34 fe aa 8d 76 01 8d 76 ff 49 76 05 77 03 d5 7e 06 0b c9 75 d3 } //1
		$a_01_1 = {66 0f ba e5 2d ac 77 04 76 02 32 ef 8d 40 fd 7c 05 7d 03 45 cc a1 8d 40 03 34 fe 71 03 70 01 1a aa c1 c9 06 c1 c1 06 49 75 03 74 01 a6 0b c9 75 cf } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}