
rule Trojan_BAT_Zusy_NY_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 20 31 57 57 35 5a 20 90 01 03 13 61 2b c9 00 20 90 01 03 ec 2b c1 7e 90 01 03 04 28 90 01 03 06 0a 07 20 90 01 03 b2 5a 20 90 01 03 9f 61 2b a7 07 20 90 01 03 e4 5a 20 90 01 03 fa 61 2b 98 90 00 } //01 00 
		$a_01_1 = {4d 65 6d 62 65 72 44 65 66 52 69 64 73 41 6c 6c 6f 63 61 74 65 64 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}