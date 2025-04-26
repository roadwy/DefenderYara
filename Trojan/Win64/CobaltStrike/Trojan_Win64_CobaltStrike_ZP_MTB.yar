
rule Trojan_Win64_CobaltStrike_ZP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZP!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 40 48 89 08 48 8b 54 24 58 48 89 50 08 48 8b 54 24 48 48 89 50 10 } //1
		$a_01_1 = {34 38 66 66 63 64 35 35 35 64 34 38 66 66 63 35 } //1 48ffcd555d48ffc5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}