
rule Trojan_Win64_Donut_NQ_MTB{
	meta:
		description = "Trojan:Win64/Donut.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 48 63 d2 48 8d 05 90 01 04 48 01 d0 48 8b 4d e0 0f be 09 0f be 10 31 d1 48 8b 45 e8 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}