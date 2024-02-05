
rule Trojan_Win32_AntiAV_MR_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c3 c1 e8 90 01 01 03 44 24 90 01 01 8d 3c 1e 33 cf c7 05 90 01 08 89 4c 24 90 01 01 81 fa 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {5f 5e 89 68 90 01 01 5d 89 18 5b 33 cc e8 90 01 04 81 c4 90 01 04 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}