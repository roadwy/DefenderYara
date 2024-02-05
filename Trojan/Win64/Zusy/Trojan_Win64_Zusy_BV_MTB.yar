
rule Trojan_Win64_Zusy_BV_MTB{
	meta:
		description = "Trojan:Win64/Zusy.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 6f 70 73 65 67 6b 66 77 6f 69 65 73 77 67 6a 69 77 6f 65 68 67 69 6f 65 72 6a } //02 00 
		$a_01_1 = {56 72 68 65 72 6f 69 67 6a 77 34 6f 69 75 67 68 6a 73 65 72 } //02 00 
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //01 00 
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}