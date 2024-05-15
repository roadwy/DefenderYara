
rule Trojan_Win64_CobaltStrike_CK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 8b d0 48 8d 49 90 01 01 83 e2 90 01 01 49 ff c0 0f b6 04 3a 32 44 0b 90 01 01 88 41 90 01 01 49 83 e9 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_CK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {30 c1 41 88 4d 0f 88 83 90 01 02 00 00 49 83 c5 10 4d 39 f5 74 90 00 } //02 00 
		$a_01_1 = {0f b6 4c 04 1f 41 30 4c 07 ff 0f b6 4c 04 20 41 30 0c 07 48 83 c0 10 48 3d 8f 00 00 00 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}