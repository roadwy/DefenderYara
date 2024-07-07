
rule Trojan_Win32_AgentTesla_FE_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 f9 00 7f 90 0a 75 00 68 e0 5e 00 00 90 02 10 59 90 02 10 83 e9 04 90 02 10 8b 1c 0f 90 02 20 31 f3 90 02 25 09 1c 08 90 02 15 83 f9 00 7f 90 00 } //1
		$a_02_1 = {68 e0 5e 00 00 90 0a 75 00 b9 90 01 03 41 90 02 10 81 c1 90 01 04 90 02 10 83 c6 02 90 02 10 4e 90 02 10 8b 1f 90 02 10 31 f3 90 02 10 39 cb 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}