
rule Trojan_BAT_Convagent_AMCU_MTB{
	meta:
		description = "Trojan:BAT/Convagent.AMCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 07 28 ?? ?? 00 06 26 00 de 0b 07 2c 07 07 6f ?? 00 00 0a 00 dc 28 ?? ?? 00 06 28 ?? ?? 00 06 26 00 de 0b } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}