
rule Trojan_Win32_Foosace_D_dha{
	meta:
		description = "Trojan:Win32/Foosace.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 2e 32 64 25 2e 32 64 25 2e 32 64 25 2e 32 64 00 } //1
		$a_01_1 = {25 00 73 00 20 00 49 00 44 00 3a 00 25 00 64 00 20 00 50 00 61 00 74 00 68 00 3a 00 00 00 } //1
		$a_01_2 = {73 00 74 00 72 00 74 00 00 00 76 00 69 00 72 00 74 00 00 00 63 00 72 00 74 00 68 00 } //1
		$a_01_3 = {2f 63 68 65 63 6b 2f 00 } //1 振敨正/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Foosace_D_dha_2{
	meta:
		description = "Trojan:Win32/Foosace.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 44 24 24 8a da c0 e3 03 8d 54 d0 fe 8d 71 02 89 54 24 2c 8d 46 01 8a d1 83 e0 07 02 d3 8d 6e ff 8a 04 38 83 e5 07 32 c2 8b d6 83 e2 07 22 04 3a 8a 54 3e fe 02 d1 02 d3 c0 e2 04 32 14 2f f6 ea 8b 54 24 2c 30 04 16 8b 44 24 28 41 46 3b c8 } //4
		$a_00_1 = {c0 e2 03 8d 71 02 8d 46 01 8a d9 83 e0 07 02 da 8d 6e ff 8a 04 38 83 e5 07 32 c3 8b de 83 e3 07 22 04 3b 8a 5c 37 fe 02 d9 02 da c0 e3 04 32 1c 2f f6 eb 8b 5c 24 28 30 04 33 41 46 83 fe 0a } //2
		$a_01_2 = {49 6e 69 74 69 61 6c 69 7a 65 } //2 Initialize
		$a_80_3 = {5c 63 68 6b 64 62 67 2e 6c 6f 67 } //\chkdbg.log  2
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}