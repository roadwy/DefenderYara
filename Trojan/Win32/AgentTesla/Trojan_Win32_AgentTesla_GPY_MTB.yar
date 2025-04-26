
rule Trojan_Win32_AgentTesla_GPY_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.GPY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 54 05 f8 8d 04 0e 30 16 83 e0 03 30 56 04 8a 4c 05 f8 8d 43 ff 30 4e 01 83 e0 03 30 4e 05 8b 8d 10 fd ff ff 8a 44 05 f8 30 46 02 8b c3 83 e0 03 83 c3 06 8a 44 05 f8 30 46 03 81 ff e2 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}