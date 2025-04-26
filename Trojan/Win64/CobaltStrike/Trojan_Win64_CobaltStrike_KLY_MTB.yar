
rule Trojan_Win64_CobaltStrike_KLY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KLY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 48 10 48 8b 41 30 48 85 c0 0f 84 db 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}