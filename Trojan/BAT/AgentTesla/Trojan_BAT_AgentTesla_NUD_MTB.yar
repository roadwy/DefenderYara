
rule Trojan_BAT_AgentTesla_NUD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {db 9a db 9c db b7 db 97 db 87 db 87 db 93 db 87 db 87 db 87 db 87 db 8b db 87 db 87 db 87 db 87 da b5 da b5 da be db 87 db 87 db 92 db ad db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 97 } //1
		$a_01_1 = {db 87 db 87 db 87 db 8d db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 8a db b2 db ad db 87 db 87 db 87 db 87 db ad db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 88 db 87 db 87 } //1
		$a_01_2 = {87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db 87 db } //1
		$a_01_3 = {69 00 7e 00 7e 00 6e 00 7e 00 7e 00 76 00 7e 00 7e 00 6f 00 7e 00 7e 00 6b 00 7e 00 7e 00 65 00 } //1 i~~n~~v~~o~~k~~e
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}