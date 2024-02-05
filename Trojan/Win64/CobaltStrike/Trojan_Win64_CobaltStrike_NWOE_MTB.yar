
rule Trojan_Win64_CobaltStrike_NWOE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NWOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 } //01 00 
		$a_81_1 = {4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //01 00 
		$a_81_2 = {53 79 73 74 65 6d 55 70 64 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}