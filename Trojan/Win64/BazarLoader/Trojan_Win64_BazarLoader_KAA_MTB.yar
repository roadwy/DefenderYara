
rule Trojan_Win64_BazarLoader_KAA_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {59 58 89 07 b8 90 01 04 48 8d 7f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}