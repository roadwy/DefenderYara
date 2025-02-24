
rule Trojan_Win32_Matanbuchus_AUJ_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.AUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 89 85 e8 fe ff ff 89 95 ec fe ff ff b8 56 27 09 00 c7 85 e0 fe ff ff 7e 6a 48 f5 89 85 e4 fe ff ff c7 85 f0 fe ff ff 1b 00 00 00 8b 0d d0 b0 07 10 66 89 4d 9c 33 d2 c7 85 d8 fe ff ff fd 00 00 00 89 95 dc fe ff ff b8 7b 29 0e 00 c7 85 d0 fe ff ff 26 ae 1e 62 89 85 d4 fe ff ff b9 54 3f 00 00 66 89 4d 98 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}