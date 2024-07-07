
rule Trojan_Win32_StealC_NIF_MTB{
	meta:
		description = "Trojan:Win32/StealC.NIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 8b c8 c1 e1 04 03 d5 03 cb 33 d1 8b 4c 24 10 03 c8 33 d1 2b f2 8b d6 c1 e2 04 c7 05 90 01 04 00 00 00 00 89 54 24 90 00 } //1
		$a_03_1 = {8b d6 c1 ea 05 03 54 24 2c c7 05 90 01 04 19 36 6b ff 33 d7 31 54 24 14 c7 05 90 01 04 ff ff ff ff 8b 44 24 14 29 44 24 18 8b 44 24 30 29 44 24 10 ff 4c 24 20 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}