
rule Trojan_BAT_AgentTesla_JDI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 0f 00 08 07 09 28 ?? ?? ?? 06 0b 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d e4 } //1
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
		$a_01_3 = {46 00 73 00 68 00 61 00 } //1 Fsha
		$a_01_4 = {43 00 46 00 34 00 54 00 34 00 35 00 34 00 41 00 43 00 38 00 30 00 35 00 5a 00 50 00 37 00 41 00 47 00 46 00 45 00 30 00 37 00 34 00 } //1 CF4T454AC805ZP7AGFE074
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}