
rule Trojan_BAT_AgentTesla_AMZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {17 da 13 05 16 13 06 2b 21 07 11 04 11 06 ?? ?? ?? ?? ?? 13 07 11 07 ?? ?? ?? ?? ?? 13 08 08 06 11 08 b4 9c 11 06 17 d6 13 06 11 06 11 05 31 d9 06 17 d6 0a 11 04 17 d6 13 04 11 04 09 31 bb } //10
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_3 = {53 69 6d 70 6c 65 55 49 2e 46 6f 72 6d 31 } //SimpleUI.Form1  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}