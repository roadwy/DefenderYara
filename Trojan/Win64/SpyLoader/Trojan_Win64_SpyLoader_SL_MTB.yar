
rule Trojan_Win64_SpyLoader_SL_MTB{
	meta:
		description = "Trojan:Win64/SpyLoader.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 f9 48 90 01 06 48 90 01 02 48 90 01 03 48 90 01 03 01 d6 6b d6 90 01 01 29 d7 48 90 01 02 42 90 01 03 32 14 0b 88 14 08 48 90 01 02 8b 95 90 01 04 48 90 01 02 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}