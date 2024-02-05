
rule Trojan_Win64_CobaltStrike_EE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 72 73 2e 71 62 6f 78 2e 6d 65 2f 63 68 74 79 70 65 2f } //01 00 
		$a_01_1 = {44 62 61 6b 2f 63 68 64 62 3a 71 69 6e 69 75 2e 70 6e 67 } //01 00 
		$a_01_2 = {52 47 4a 68 61 79 39 6a 61 47 52 69 4f 6e 46 70 62 6d 6c 31 4c 6e 42 75 5a 77 3d 3d } //01 00 
		$a_01_3 = {41 63 71 75 69 72 65 43 72 65 64 65 6e 74 69 61 6c 73 48 61 6e 64 6c 65 } //01 00 
		$a_01_4 = {62 61 73 65 36 34 20 65 6e 63 6f 64 69 6e 67 } //01 00 
		$a_01_5 = {4b 65 72 62 65 72 6f 73 } //00 00 
	condition:
		any of ($a_*)
 
}