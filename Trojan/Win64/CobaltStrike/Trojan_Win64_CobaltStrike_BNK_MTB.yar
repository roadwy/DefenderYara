
rule Trojan_Win64_CobaltStrike_BNK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BNK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 89 bc 24 80 00 00 00 48 8b 48 18 4c 8b 59 20 4d 85 db } //1
		$a_01_1 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}