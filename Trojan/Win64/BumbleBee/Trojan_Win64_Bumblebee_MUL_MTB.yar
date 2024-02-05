
rule Trojan_Win64_Bumblebee_MUL_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 8d 0c 03 4d 2b f3 49 8b f3 4c 89 b4 24 90 01 04 4c 2b c0 43 8a 0c 0e 2a 8c 24 90 01 04 32 8c 24 90 01 04 49 8b 42 48 41 88 0c 01 83 ff 90 01 01 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}