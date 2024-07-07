
rule Trojan_Win64_CobaltStrike_AMX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 08 41 8b d0 33 d0 } //1
		$a_01_1 = {2b c1 48 63 c8 48 8b 44 24 30 88 14 08 e9 8a fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}