
rule Trojan_BAT_AgentTesla_DDZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 11 04 28 ?? ?? ?? 0a 23 00 00 00 00 00 80 73 40 59 28 ?? ?? ?? 0a b7 13 05 07 11 05 28 ?? ?? ?? 0a 8c ?? ?? ?? 01 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 8e 69 } //1
		$a_01_1 = {49 00 52 00 6e 00 52 00 76 00 52 00 6f 00 52 00 6b 00 52 00 65 00 } //1 IRnRvRoRkRe
		$a_01_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}