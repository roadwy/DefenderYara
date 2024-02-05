
rule Trojan_Win32_GandCrypt_PVD_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 d0 89 15 90 01 04 81 f9 66 0d 00 00 73 90 09 0d 00 0f b6 81 90 01 04 03 05 90 00 } //01 00 
		$a_02_1 = {30 04 2e 83 ee 01 79 90 09 05 00 e8 90 00 } //02 00 
		$a_02_2 = {8b ce 8b c6 c1 e1 04 03 0d 90 01 04 c1 e8 05 03 05 90 01 04 33 c8 8d 04 37 2b 7d fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}