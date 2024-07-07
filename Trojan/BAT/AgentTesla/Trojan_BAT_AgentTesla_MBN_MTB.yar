
rule Trojan_BAT_AgentTesla_MBN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 18 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 0b 02 28 90 01 01 00 00 0a 0c 07 08 16 08 8e 69 6f 90 01 01 00 00 0a 0d 09 13 04 de 0b 90 00 } //1
		$a_01_1 = {6c 00 62 00 6c 00 41 00 62 00 6f 00 75 00 74 00 43 00 48 00 54 00 2e 00 54 00 65 00 78 00 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}