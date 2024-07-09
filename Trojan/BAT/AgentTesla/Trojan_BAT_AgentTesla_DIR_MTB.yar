
rule Trojan_BAT_AgentTesla_DIR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0c 07 08 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d de 15 07 2c 06 07 6f ?? ?? ?? 0a dc 90 09 11 00 73 ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a } //1
		$a_01_1 = {00 54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b 00 } //1
		$a_01_2 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00 } //1
		$a_01_3 = {00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}