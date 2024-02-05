
rule Trojan_Win64_Sarupx_RDA_MTB{
	meta:
		description = "Trojan:Win64/Sarupx.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 8d 42 01 44 0f b6 d0 42 0f b6 54 14 60 41 8d 04 11 44 0f b6 c8 42 8a 44 0c 60 42 88 44 14 60 42 88 54 0c 60 42 0f b6 44 14 60 03 c2 99 41 23 d4 03 c2 41 23 c4 2b c2 8a 44 04 60 41 30 00 49 ff c0 49 83 eb 01 } //00 00 
	condition:
		any of ($a_*)
 
}