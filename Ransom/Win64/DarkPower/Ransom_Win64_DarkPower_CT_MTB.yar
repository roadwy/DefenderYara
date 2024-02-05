
rule Ransom_Win64_DarkPower_CT_MTB{
	meta:
		description = "Ransom:Win64/DarkPower.CT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 5c 24 60 48 23 5c 24 68 48 31 cb 48 8b 4c 24 50 48 31 d3 48 23 8c 24 90 00 00 00 48 33 4c 24 28 4d 31 f9 48 33 4c 24 30 4d 31 d9 48 31 c1 48 8b 44 24 48 4c 31 d1 } //00 00 
	condition:
		any of ($a_*)
 
}