
rule Trojan_Win64_Iceid_PBG_MTB{
	meta:
		description = "Trojan:Win64/Iceid.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8d 49 01 83 e0 03 90 13 ff c2 0f b6 44 38 2c 90 13 30 41 ff 3b d6 90 13 8b c2 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}