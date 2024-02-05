
rule Trojan_Win64_Perfusion_RPQ_MTB{
	meta:
		description = "Trojan:Win64/Perfusion.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 0f b7 03 66 41 83 f8 2e 74 4e 66 41 83 f8 5f 75 08 41 ff c2 48 8b cb eb 31 48 83 f9 0a 7d 2b 41 8b d2 83 ea 01 74 1a 83 ea 01 74 0d 83 fa 01 75 19 66 44 89 44 4c 48 eb 0e 66 44 89 44 4d b0 eb 06 66 44 89 44 4d 00 48 ff c1 ff c7 49 83 c3 02 48 63 c7 49 3b c1 72 a7 } //00 00 
	condition:
		any of ($a_*)
 
}