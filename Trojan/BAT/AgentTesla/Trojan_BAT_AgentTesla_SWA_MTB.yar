
rule Trojan_BAT_AgentTesla_SWA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 03 07 20 ef be ad de 28 4d 00 00 06 0c 02 08 7e 40 00 00 04 07 19 5f 94 23 18 2d 44 54 fb 21 09 40 28 4a 00 00 06 00 00 07 17 58 0b 07 06 20 cd ab 34 12 6a 28 4c 00 00 06 0d 09 2d c2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}