
rule Trojan_Win64_CobaltStrike_CRDP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CRDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 73 70 6f 72 76 6a 6c 66 73 71 6d 6c 73 61 6d 78 64 72 76 69 74 78 68 61 } //01 00 
		$a_01_1 = {71 65 65 62 76 69 61 6b 73 65 76 6a 74 77 } //01 00 
		$a_01_2 = {65 65 70 66 74 71 6a 66 68 75 64 75 65 74 68 7a 75 6f 6a 77 70 72 74 6b 70 63 } //01 00 
		$a_01_3 = {73 6a 78 66 77 6e 73 6f 70 75 66 71 71 6a 79 79 6a 6e 6b 74 } //00 00 
	condition:
		any of ($a_*)
 
}