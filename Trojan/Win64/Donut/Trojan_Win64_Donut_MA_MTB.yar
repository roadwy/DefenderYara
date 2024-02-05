
rule Trojan_Win64_Donut_MA_MTB{
	meta:
		description = "Trojan:Win64/Donut.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 63 50 44 48 8b 48 60 46 8b 0c 11 49 83 c2 04 44 0f af 48 40 48 8b 48 68 45 8b c1 41 c1 e8 08 44 88 04 0a ff 40 44 } //00 00 
	condition:
		any of ($a_*)
 
}