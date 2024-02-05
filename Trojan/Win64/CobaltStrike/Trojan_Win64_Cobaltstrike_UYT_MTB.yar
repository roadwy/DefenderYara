
rule Trojan_Win64_Cobaltstrike_UYT_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.UYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 3d 94 60 02 00 8b c7 83 e0 3f 2b c8 49 8b c4 48 d3 c8 48 8b cb 49 2b c8 48 33 c7 48 83 c1 07 48 c1 e9 03 4c 3b c3 49 0f 47 cc } //00 00 
	condition:
		any of ($a_*)
 
}