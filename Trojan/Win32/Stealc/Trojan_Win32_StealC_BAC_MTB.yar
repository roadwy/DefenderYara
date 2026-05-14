
rule Trojan_Win32_StealC_BAC_MTB{
	meta:
		description = "Trojan:Win32/StealC.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 8b 46 50 c7 44 24 20 40 00 00 00 33 d2 41 b9 00 30 00 00 48 8b 4c 24 50 ff 15 } //2
		$a_01_1 = {45 8b 4e 54 4c 89 6c 24 20 4c 8b c3 48 8b d0 48 8b 4c 24 50 ff 15 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}