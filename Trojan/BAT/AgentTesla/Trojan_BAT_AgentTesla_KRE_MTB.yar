
rule Trojan_BAT_AgentTesla_KRE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 b4 00 00 5d 07 09 20 00 b4 00 00 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 6a 07 09 17 58 20 00 b4 00 00 5d 91 28 ?? ?? ?? 0a 6e 59 20 00 01 00 00 6a 58 20 00 01 00 00 6a 5d d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d ae } //10
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {52 00 69 00 73 00 6b 00 47 00 61 00 6d 00 65 00 } //1 RiskGame
		$a_01_4 = {50 00 37 00 43 00 34 00 35 00 35 00 52 00 46 00 38 00 45 00 42 00 43 00 59 00 48 00 41 00 38 00 55 00 52 00 4a 00 35 00 38 00 35 00 } //1 P7C455RF8EBCYHA8URJ585
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}