
rule Trojan_Win64_Dridex_RPJ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {41 88 1c 3a 03 8c 24 90 01 04 66 44 8b 4c 24 90 01 01 66 41 83 f1 90 01 01 66 44 89 8c 24 90 01 04 8b 94 24 90 01 04 4c 8b 94 24 90 01 04 4c 89 94 24 90 01 04 89 8c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}