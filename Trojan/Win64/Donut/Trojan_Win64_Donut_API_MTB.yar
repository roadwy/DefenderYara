
rule Trojan_Win64_Donut_API_MTB{
	meta:
		description = "Trojan:Win64/Donut.API!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 48 63 c0 48 8b 4d e8 48 01 c1 8b 45 e4 48 63 c0 48 8b 55 10 48 01 c2 8b 45 e4 48 89 4d d8 8b 4d f4 48 89 55 d0 99 f7 f9 48 63 d2 48 8b 45 f8 48 01 d0 48 8b 4d d0 0f be 09 0f be 10 31 d1 48 8b 45 d8 88 08 } //00 00 
	condition:
		any of ($a_*)
 
}