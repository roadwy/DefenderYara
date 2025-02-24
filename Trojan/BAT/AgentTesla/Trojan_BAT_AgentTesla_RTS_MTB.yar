
rule Trojan_BAT_AgentTesla_RTS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {19 8d 18 00 00 01 25 16 72 01 00 00 70 28 16 00 00 0a 73 17 00 00 0a a2 25 17 72 13 00 00 70 28 16 00 00 0a 73 17 00 00 0a a2 25 18 72 21 00 00 70 } //2
		$a_81_1 = {73 45 4f 71 2e 65 78 65 } //1 sEOq.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}