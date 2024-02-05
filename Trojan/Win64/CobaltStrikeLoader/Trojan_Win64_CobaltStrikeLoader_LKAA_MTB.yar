
rule Trojan_Win64_CobaltStrikeLoader_LKAA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeLoader.LKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 0f b6 0c 02 90 02 20 41 31 c9 44 88 cb 90 02 0c 41 88 1c 30 90 01 03 83 c0 01 89 45 cc e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}