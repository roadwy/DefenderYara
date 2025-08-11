
rule Trojan_Win64_ACRStealer_ETL_MTB{
	meta:
		description = "Trojan:Win64/ACRStealer.ETL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 20 48 c7 40 10 12 00 00 00 48 8d 0d f8 a0 01 00 48 89 48 08 48 8b 4c 24 38 48 89 4c 24 30 48 8d 05 40 8d 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}