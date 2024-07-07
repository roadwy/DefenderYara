
rule Trojan_BAT_AgentTesla_APT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.APT!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 5b 02 00 70 72 5f 02 00 70 6f 50 00 00 0a 72 67 02 00 70 72 6b 02 00 70 6f 50 00 00 0a 72 6f 02 00 70 72 73 02 00 70 6f 50 00 00 0a 0a 06 17 8d 45 00 00 01 25 16 1f 2d 9d 6f 51 00 00 0a 0b } //1
		$a_01_1 = {08 11 07 07 11 07 9a 1f 10 28 53 00 00 0a d2 6f 54 00 00 0a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}