
rule Trojan_BAT_Bladabindi_NG_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e 30 00 00 04 0e 06 17 59 95 58 0e 05 28 ?? 02 00 06 58 54 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Bladabindi_NG_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 09 11 09 16 72 ?? ?? ?? ?? a2 00 11 09 16 6f ?? ?? ?? ?? 13 07 11 07 16 9a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0c 11 07 8e b7 19 2e 06 11 07 17 9a 2b 0e 11 07 17 9a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 10 01 06 11 04 28 ?? ?? ?? ?? 04 6f [0-15] 0a 00 06 08 28 ?? ?? ?? ?? ?? ?? ?? ?? 0a 00 06 17 } //1
		$a_01_1 = {15 a2 09 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 7b 00 00 00 10 00 00 00 35 00 00 00 86 00 00 00 44 00 00 00 d1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}