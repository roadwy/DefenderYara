
rule Trojan_BAT_AgentTesla_MAAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 00 58 00 55 00 31 00 33 00 55 00 38 00 45 00 58 00 58 00 58 00 55 00 43 00 30 00 58 00 58 00 55 00 30 00 46 00 58 00 58 00 } //1 XXU13U8EXXXUC0XXU0FXX
		$a_01_1 = {58 00 55 00 30 00 33 00 58 00 55 00 45 00 32 00 58 00 55 00 30 00 33 00 58 00 55 00 45 00 32 00 58 00 55 00 30 00 33 00 58 00 55 00 45 00 32 00 58 00 55 00 } //1 XU03XUE2XU03XUE2XU03XUE2XU
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}