
rule Trojan_Win64_Bumblebee_FB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.FB!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 4f 5a 7a 34 36 50 78 } //01 00 
		$a_01_1 = {54 66 4c 58 76 31 32 6b } //01 00 
		$a_01_2 = {56 52 49 5a 53 36 70 } //05 00 
		$a_01_3 = {63 6d 66 67 75 74 69 6c } //00 00 
	condition:
		any of ($a_*)
 
}