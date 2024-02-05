
rule Trojan_Win64_CobaltStrike_CL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {42 0f b6 04 07 41 32 04 24 88 44 24 90 01 01 4c 8b 6e 90 01 01 4c 8d 4c 24 90 01 01 4d 8b c5 48 8b d6 e8 90 01 04 48 b9 90 01 08 48 8b 54 24 90 01 01 48 2b ca 48 83 f9 90 01 01 0f 82 90 01 04 48 ff c2 48 90 01 04 48 89 46 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}