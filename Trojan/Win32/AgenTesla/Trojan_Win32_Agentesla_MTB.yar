
rule Trojan_Win32_Agentesla_MTB{
	meta:
		description = "Trojan:Win32/Agentesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 37 32 da 32 d8 32 d9 88 1e 8a d8 32 d9 22 da 8b 55 14 8d 3c d5 00 00 00 00 33 fa 81 e7 90 01 02 00 00 c1 e7 14 c1 ea 08 0b d7 8d 3c 00 33 f8 22 c8 c1 e7 04 33 f8 32 cb 8b d8 83 e7 90 01 01 c1 e3 07 33 fb c1 e7 90 01 01 c1 e8 08 0b c7 46 ff 4d 10 89 55 14 75 a9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}