
rule Trojan_Win64_CobaltStrike_JN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 8a 44 0c 90 01 01 41 8d 40 90 01 01 3c 90 01 01 77 90 01 01 41 80 e8 90 01 01 44 88 44 0c 90 01 01 48 ff c1 49 3b ca 7c 90 00 } //01 00 
		$a_03_1 = {41 8b c1 f7 d8 8d 3c 87 41 69 00 90 01 04 49 83 c0 90 01 01 69 f6 90 01 04 8b c8 c1 e9 90 01 01 33 c8 69 c9 90 01 04 33 f1 49 83 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}