
rule Trojan_Win64_CobaltStrike_YR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 30 00 00 00 48 8b 40 60 48 8b 40 18 48 8b 40 20 4c 8b 18 4d 8d 53 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}