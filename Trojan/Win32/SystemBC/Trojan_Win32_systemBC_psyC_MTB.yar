
rule Trojan_Win32_systemBC_psyC_MTB{
	meta:
		description = "Trojan:Win32/systemBC.psyC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {9b c7 48 87 fe 66 0f b6 d1 f7 d2 5a 0f be d8 66 0f cb 5b 48 8d b0 14 be e9 c6 66 f7 d7 e9 42 03 00 00 0f 82 d7 ff ff ff 66 0f ba e2 06 80 fb bc } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}