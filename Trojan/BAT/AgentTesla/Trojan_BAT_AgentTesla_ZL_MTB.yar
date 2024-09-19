
rule Trojan_BAT_AgentTesla_ZL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 23 48 e1 7a 14 ae 47 e1 3f 23 71 3d 0a d7 a3 70 dd 3f 23 18 2d 44 54 fb 21 19 40 09 6c 5a 03 17 da 6c 5b 28 7a 00 00 0a 5a 59 a1 09 17 d6 0d 09 08 31 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}