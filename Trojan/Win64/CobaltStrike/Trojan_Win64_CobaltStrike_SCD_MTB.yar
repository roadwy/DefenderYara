
rule Trojan_Win64_CobaltStrike_SCD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 4c 8b 49 10 49 8b 49 30 48 85 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_SCD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.SCD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 50 02 48 89 55 10 0f b7 00 0f b6 c0 31 45 fc 8b 45 fc 69 c0 fb e3 ed 25 89 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}