
rule Trojan_Win64_Androm_RG_MTB{
	meta:
		description = "Trojan:Win64/Androm.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 44 24 38 48 8b 4c 24 20 0f be 09 33 c8 8b c1 48 8b 4c 24 20 88 01 48 8b 44 24 20 48 ff c0 48 89 44 24 20 eb c5 } //00 00 
	condition:
		any of ($a_*)
 
}