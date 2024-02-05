
rule Trojan_Win64_Cobaltstrike_FG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 44 24 28 00 00 00 00 8b 44 24 24 48 63 4c 24 28 0f b6 4c 0c 50 48 8b 94 24 90 01 04 0f b6 04 02 33 c1 8b 4c 24 24 48 8b 94 24 90 01 04 88 04 0a 8b 44 24 28 ff c0 89 44 24 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}