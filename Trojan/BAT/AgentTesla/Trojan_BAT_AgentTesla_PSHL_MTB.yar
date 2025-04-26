
rule Trojan_BAT_AgentTesla_PSHL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 03 00 00 0a 28 12 00 00 06 6f 04 00 00 0a 0a 06 6f 05 00 00 0a 0b 07 18 5b 8d 05 00 00 01 0c 16 0d 2b 18 08 09 18 5b 06 09 18 6f 06 00 00 0a 1f 10 28 07 00 00 0a 9c 09 18 58 0d 09 07 32 e4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}