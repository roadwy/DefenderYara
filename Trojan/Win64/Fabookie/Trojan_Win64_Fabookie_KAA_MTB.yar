
rule Trojan_Win64_Fabookie_KAA_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 03 cf 48 8d 55 90 01 01 41 b8 90 01 04 e8 90 01 04 85 c0 74 14 ff c3 48 63 cb 48 81 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}