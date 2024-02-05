
rule Trojan_Win64_Bumblebee_KKK_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.KKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 83 c1 04 01 43 90 01 01 8b 43 90 01 01 2b 43 90 01 01 90 01 04 11 01 83 90 01 04 8b 43 90 01 01 35 90 01 04 29 83 90 01 04 8b 83 90 01 04 01 43 90 01 01 8b 43 90 01 01 2b 83 90 01 04 05 90 01 04 09 83 90 01 04 49 81 f9 90 01 04 7c 90 00 } //01 00 
		$a_01_1 = {62 59 58 6a 64 45 52 79 6d 73 46 59 } //00 00 
	condition:
		any of ($a_*)
 
}