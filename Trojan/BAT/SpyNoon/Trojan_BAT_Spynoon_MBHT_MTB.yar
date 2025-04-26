
rule Trojan_BAT_Spynoon_MBHT_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.MBHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 6a 00 30 00 63 00 48 00 4d 00 4e 00 66 00 76 00 52 00 38 00 58 00 70 00 56 00 6b 00 4a 00 6f 00 43 00 2e 00 44 00 50 00 45 00 49 00 6e 00 65 00 51 00 71 00 64 00 77 00 74 00 74 00 70 00 34 00 67 00 56 00 72 00 6c 00 } //1 Aj0cHMNfvR8XpVkJoC.DPEIneQqdwttp4gVrl
		$a_01_1 = {45 00 65 00 37 00 62 00 56 00 73 00 76 00 69 00 50 00 } //1 Ee7bVsviP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}