
rule Trojan_Win32_Dizemp_GKL_MTB{
	meta:
		description = "Trojan:Win32/Dizemp.GKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 40 0c 8b 00 8b 00 b9 90 01 04 33 c1 89 85 90 01 04 b9 90 01 04 83 e9 90 01 01 86 e9 66 89 8d 90 01 04 66 c7 85 90 01 06 6a 10 8d 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}