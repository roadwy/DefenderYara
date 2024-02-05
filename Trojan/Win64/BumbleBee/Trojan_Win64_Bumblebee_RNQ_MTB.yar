
rule Trojan_Win64_Bumblebee_RNQ_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.RNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 2b eb 4d 8b cb 4c 2b c1 49 8b 4a 90 01 01 48 8b 81 90 01 04 49 0f af c6 48 29 41 90 01 01 42 8a 0c 2f 2a 4c 24 90 01 01 32 4c 24 50 49 8b 42 90 01 01 88 0c 07 83 fe 08 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}