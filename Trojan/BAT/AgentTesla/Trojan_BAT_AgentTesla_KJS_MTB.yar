
rule Trojan_BAT_AgentTesla_KJS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {2b 00 6b 00 7e 00 7e 00 7e 00 4b 00 4c 00 65 00 44 00 65 00 43 00 67 00 59 00 } //1 +k~~~KLeDeCgY
		$a_01_1 = {63 00 6d 00 39 00 6e 00 63 00 6d 00 46 00 74 00 49 00 47 00 4e 00 } //1 cm9ncmFtIGN
		$a_01_2 = {2b 00 47 00 77 00 7e 00 7e 00 42 00 42 00 6b 00 52 00 46 00 46 00 38 00 5a 00 } //1 +Gw~~BBkRFF8Z
		$a_01_3 = {55 00 62 00 31 00 51 00 7e 00 7e 00 7e 00 6f 00 6d 00 4b 00 67 00 7e 00 54 00 4d 00 7e 00 49 00 7e 00 44 00 67 00 } //1 Ub1Q~~~omKg~TM~I~Dg
		$a_01_4 = {2b 00 6e 00 7e 00 7e 00 7e 00 47 00 62 00 35 00 63 00 } //1 +n~~~Gb5c
		$a_01_5 = {45 76 65 6e 74 4c 69 73 74 65 6e 65 72 } //1 EventListener
		$a_80_6 = {46 72 6f 6d 42 61 73 65 36 34 } //FromBase64  1
		$a_80_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}