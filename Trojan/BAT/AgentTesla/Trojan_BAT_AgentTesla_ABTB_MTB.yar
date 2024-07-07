
rule Trojan_BAT_AgentTesla_ABTB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 07 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a b4 6f 90 01 03 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc 90 00 } //5
		$a_01_1 = {4d 00 61 00 72 00 6c 00 69 00 65 00 63 00 65 00 20 00 41 00 6e 00 64 00 72 00 61 00 64 00 61 00 } //1 Marliece Andrada
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}