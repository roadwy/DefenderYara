
rule Trojan_Win32_Bandit_GC_MTB{
	meta:
		description = "Trojan:Win32/Bandit.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c0 7b 89 04 24 b8 f9 cd 03 00 01 04 24 83 2c 24 7b 8b 04 24 8a 04 08 88 04 0a 59 c3 90 09 0c 00 51 a1 90 01 04 8b 15 90 00 } //1
		$a_02_1 = {8b cb 89 44 24 10 8d 04 1f c1 e9 05 03 4c 24 3c 89 44 24 1c 89 35 90 01 04 89 35 90 01 04 8b 44 24 1c 31 44 24 10 81 3d 90 01 04 72 07 00 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}