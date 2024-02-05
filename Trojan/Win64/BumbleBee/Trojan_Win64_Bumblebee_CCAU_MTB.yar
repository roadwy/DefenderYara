
rule Trojan_Win64_Bumblebee_CCAU_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.CCAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 43 58 8b 43 38 03 83 c4 00 00 00 33 05 90 01 04 35 90 01 04 89 05 90 01 04 b8 11 00 00 00 2b 83 e0 00 00 00 01 43 54 48 8b 0d 90 01 04 8b 43 04 29 41 3c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}