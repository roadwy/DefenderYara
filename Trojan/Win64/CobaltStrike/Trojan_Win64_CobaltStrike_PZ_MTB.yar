
rule Trojan_Win64_CobaltStrike_PZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b f0 65 48 8b 0c 25 60 00 00 00 48 8b 49 18 48 8b 49 10 4c 8b 59 30 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}