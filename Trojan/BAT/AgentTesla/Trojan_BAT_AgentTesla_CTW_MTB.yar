
rule Trojan_BAT_AgentTesla_CTW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 66 56 4f 58 6f 59 71 68 6a 72 79 7a 45 61 58 6b 74 78 69 } //1 RfVOXoYqhjryzEaXktxi
		$a_81_1 = {44 54 71 4c 59 4f 72 73 50 45 4f 76 6d 4c } //1 DTqLYOrsPEOvmL
		$a_81_2 = {54 6b 43 53 65 48 51 62 6d 7a 79 70 7a 48 47 6c 55 41 65 6f 42 7a 77 42 44 55 65 4a } //1 TkCSeHQbmzypzHGlUAeoBzwBDUeJ
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=2
 
}