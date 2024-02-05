
rule Trojan_Win64_Havokiz_SA_MTB{
	meta:
		description = "Trojan:Win64/Havokiz.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 0f b6 c0 0f af d0 48 90 01 06 88 14 01 ff 43 90 01 01 48 90 01 06 8b 4b 90 01 01 2b 48 90 01 01 8b 83 90 01 04 83 c1 90 01 01 01 8b 90 01 04 09 05 90 01 04 48 8b 05 90 01 04 8b 48 90 01 01 33 8b 90 01 04 83 e9 90 01 01 09 4b 90 01 01 48 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}