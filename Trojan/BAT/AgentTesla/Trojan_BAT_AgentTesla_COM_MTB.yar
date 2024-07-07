
rule Trojan_BAT_AgentTesla_COM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.COM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 06 11 04 18 d8 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 11 04 17 d6 13 04 11 04 09 31 90 00 } //1
		$a_01_1 = {73 00 65 00 70 00 79 00 54 00 74 00 65 00 47 00 } //1 sepyTteG
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}