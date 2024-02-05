
rule Trojan_Win64_CobaltStrike_KJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 44 24 20 04 00 00 00 41 b9 00 10 00 00 41 b8 90 00 00 00 48 8b ce ff 15 } //01 00 
		$a_01_1 = {6c 65 67 61 63 79 2e 63 68 75 6e 6b 2e 6a 73 } //01 00 
		$a_03_2 = {77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 90 02 02 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}