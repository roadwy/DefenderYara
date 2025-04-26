
rule Trojan_BAT_AgentTesla_FAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 2c 21 26 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 01 00 06 74 ?? 00 00 1b 28 ?? 01 00 06 17 2d 06 26 de 09 0a 2b dd 0b 2b f8 26 de c8 } //3
		$a_01_1 = {73 00 70 00 62 00 2d 00 67 00 61 00 6e 00 2e 00 72 00 75 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 44 00 65 00 63 00 6a 00 75 00 2e 00 62 00 6d 00 70 00 } //2 spb-gan.ru/panel/uploads/Decju.bmp
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}