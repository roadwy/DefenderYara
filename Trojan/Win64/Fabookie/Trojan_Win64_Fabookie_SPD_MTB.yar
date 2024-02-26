
rule Trojan_Win64_Fabookie_SPD_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {48 03 cf 48 8d 55 e0 41 b8 16 00 00 00 e8 7c 12 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 } //00 00 
	condition:
		any of ($a_*)
 
}