
rule Trojan_Win64_CobaltStrike_SCD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SCD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 50 02 48 89 55 10 0f b7 00 0f b6 c0 31 45 fc 8b 45 fc 69 c0 fb e3 ed 25 89 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}