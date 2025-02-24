
rule Trojan_Win32_StealC_A_MTB{
	meta:
		description = "Trojan:Win32/StealC.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 04 0f 31 45 ?? 8b f9 8b 4d ?? d3 ef 03 7d } //2
		$a_03_1 = {c6 05 01 c1 42 00 6c c6 05 fb c0 42 00 6d c6 05 fc c0 42 00 67 c6 05 00 c1 42 00 64 c6 05 03 c1 42 00 ?? c6 05 02 c1 42 00 6c c6 05 ff c0 42 00 2e c6 05 fe c0 42 00 32 c6 05 f8 c0 42 00 6d c6 05 fa c0 42 00 69 c6 05 fd c0 42 00 33 c6 05 f9 c0 42 00 73 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}
rule Trojan_Win32_StealC_A_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 8b 45 f0 89 45 c8 8b 45 c8 8b 40 3c 8b 4d f0 8d 44 01 04 89 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_StealC_A_MTB_3{
	meta:
		description = "Trojan:Win32/StealC.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 14 56 57 8b 7d 08 33 f6 89 47 0c 39 75 10 76 15 8b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}