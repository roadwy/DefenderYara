
rule Trojan_Win64_Zusy_RB_MTB{
	meta:
		description = "Trojan:Win64/Zusy.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 8b c9 66 90 8d 41 a5 30 04 0a 48 ff c1 48 83 f9 0c 72 f1 c6 42 0d 00 } //01 00 
		$a_01_1 = {70 6f 6f 66 65 72 5f 75 70 64 61 74 65 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}