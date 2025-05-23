
rule Trojan_Win64_Rootkitdrv_A{
	meta:
		description = "Trojan:Win64/Rootkitdrv.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {44 46 75 6e 63 00 00 00 45 78 70 6f 72 74 46 75 6e 63 00 [0-8a] 68 65 61 64 4c 69 62 00 } //1
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 4e 00 54 00 46 00 49 00 4c 00 54 00 45 00 52 00 00 00 } //1
		$a_01_2 = {54 68 33 4e 00 } //1
		$a_00_3 = {61 6d 64 36 34 5c 61 6d 64 36 34 5c 50 6f 69 6e 74 46 69 6c 74 65 72 2e 70 64 62 00 } //1
		$a_00_4 = {3a c3 74 1e b8 4d 5a 00 00 66 3b 07 75 14 48 63 57 3c 48 03 d7 81 3a 50 45 00 00 48 0f 45 d3 48 8b da 48 8b c3 48 8b 5c 24 30 } //1
		$a_00_5 = {49 3b f7 74 1d 81 3e 52 53 44 53 75 15 48 83 c9 ff 33 c0 48 8d 7e 18 f2 ae 48 f7 d1 48 2b cb 4c 8b f1 48 8b 4d 18 45 8b e7 e8 } //1
		$a_02_6 = {c7 44 24 28 80 00 00 00 c7 44 24 20 03 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f8 48 85 c0 74 21 4c 8d 4c 24 48 4c 8d 44 24 40 48 8d 54 24 50 48 8b c8 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1) >=3
 
}
rule Trojan_Win64_Rootkitdrv_A_2{
	meta:
		description = "Trojan:Win64/Rootkitdrv.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 3a 5c 67 69 74 5c 72 6b 5c 72 6b 5c 5f 4f 55 54 5c 48 6c 70 53 59 53 36 34 2e 70 64 62 } //1 G:\git\rk\rk\_OUT\HlpSYS64.pdb
		$a_01_1 = {49 50 49 6e 6a 65 63 74 50 6b 74 } //1 IPInjectPkt
		$a_01_2 = {4b 00 64 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 } //1 KdDisableDebugger
		$a_01_3 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 62 00 65 00 65 00 70 00 2e 00 73 00 79 00 73 00 } //1 C:\Windows\system32\drivers\beep.sys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}