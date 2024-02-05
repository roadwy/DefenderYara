
rule Trojan_Win64_NighthawkRAT_PA_MTB{
	meta:
		description = "Trojan:Win64/NighthawkRAT.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6e 48 8d 0d 90 02 06 51 5a 48 81 c1 90 02 06 48 81 c2 90 02 06 ff e2 90 00 } //01 00 
		$a_01_1 = {66 03 d2 66 33 d1 66 c1 e2 02 66 33 d1 66 23 d0 0f b7 c1 0f 5f d2 99 91 3c } //00 00 
	condition:
		any of ($a_*)
 
}