
rule Trojan_BAT_AgentTesla_MBDK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 66 00 76 00 6d 00 66 00 65 00 58 00 51 00 61 00 4e 00 4e 00 57 00 4a 00 31 00 51 00 53 00 58 00 67 00 30 00 4d 00 55 00 65 00 55 00 73 00 44 00 63 00 70 00 7a 00 4b 00 56 00 4e 00 52 00 47 00 53 00 66 00 7a 00 33 00 4a 00 } //1 jfvmfeXQaNNWJ1QSXg0MUeUsDcpzKVNRGSfz3J
	condition:
		((#a_01_0  & 1)*1) >=1
 
}