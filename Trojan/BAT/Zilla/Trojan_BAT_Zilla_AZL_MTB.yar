
rule Trojan_BAT_Zilla_AZL_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 16 0c 2b 74 20 f4 01 00 00 28 ?? 00 00 0a 12 03 fe 15 ?? 00 00 02 12 03 28 ?? 00 00 06 2d 0e 03 72 ?? 17 00 70 6f ?? 00 00 0a 26 2b 47 09 7b ?? 00 00 04 07 7b ?? 00 00 04 33 0e 09 7b ?? 00 00 04 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Zilla_AZL_MTB_2{
	meta:
		description = "Trojan:BAT/Zilla.AZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 1c 07 08 9a 0d 09 72 ?? 0f 00 70 6f ?? 00 00 0a 2c 07 06 09 6f ?? 01 00 0a 08 17 58 0c 08 07 8e 69 32 de } //2
		$a_03_1 = {2c 01 2a 00 73 ?? 00 00 0a 0c 08 07 06 6f ?? 00 00 0a de 0a 08 2c 06 08 6f } //1
		$a_01_2 = {76 00 69 00 70 00 2e 00 31 00 32 00 33 00 70 00 61 00 6e 00 2e 00 63 00 6e 00 2f 00 } //5 vip.123pan.cn/
		$a_01_3 = {33 00 39 00 2e 00 31 00 30 00 36 00 2e 00 31 00 33 00 33 00 2e 00 32 00 32 00 33 00 } //3 39.106.133.223
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3) >=11
 
}
rule Trojan_BAT_Zilla_AZL_MTB_3{
	meta:
		description = "Trojan:BAT/Zilla.AZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 00 25 16 6f ?? 00 00 0a 00 0a 06 28 ?? 00 00 0a 0b 07 6f ?? 00 00 0a 00 72 59 00 00 70 28 ?? 00 00 06 26 28 ?? 00 00 06 0c 08 1b 28 ?? 00 00 06 26 08 28 ?? 00 00 06 00 1f 32 1f 14 28 } //2
		$a_01_1 = {57 00 65 00 6c 00 63 00 6f 00 6d 00 65 00 20 00 74 00 6f 00 20 00 44 00 79 00 6e 00 58 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Welcome to DynX Corporation
		$a_01_2 = {45 00 6d 00 75 00 6c 00 61 00 74 00 6f 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //1 Emulator Detected
		$a_01_3 = {56 41 5a 41 41 44 20 43 4d 44 20 53 45 43 55 52 45 5c 44 6f 77 6e 6c 6f 61 64 65 72 5c 6f 62 6a 5c 44 65 62 75 67 } //1 VAZAAD CMD SECURE\Downloader\obj\Debug
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_BAT_Zilla_AZL_MTB_4{
	meta:
		description = "Trojan:BAT/Zilla.AZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 00 38 00 35 00 2e 00 31 00 32 00 35 00 2e 00 35 00 30 00 2e 00 32 00 30 00 } //5 185.125.50.20
		$a_01_1 = {67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 4e 00 69 00 6b 00 6f 00 42 00 61 00 62 00 62 00 79 00 2f 00 6e 00 69 00 6b 00 65 00 6c 00 69 00 76 00 65 00 2f 00 72 00 61 00 77 00 2f 00 72 00 65 00 66 00 73 00 2f 00 68 00 65 00 61 00 64 00 73 00 2f 00 6d 00 61 00 69 00 6e 00 2f 00 74 00 6f 00 72 00 2e 00 74 00 78 00 74 00 } //4 github.com/NikoBabby/nikelive/raw/refs/heads/main/tor.txt
		$a_01_2 = {53 69 6c 65 6e 74 5c 53 69 6c 65 6e 74 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 74 6f 72 65 2e 70 64 62 } //3 Silent\Silent\obj\Release\tore.pdb
		$a_01_3 = {72 00 61 00 77 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 54 00 72 00 6f 00 6f 00 74 00 30 00 46 00 6f 00 62 00 69 00 61 00 2f 00 54 00 65 00 73 00 74 00 46 00 69 00 6c 00 65 00 2f 00 72 00 65 00 66 00 73 00 2f 00 68 00 65 00 61 00 64 00 73 00 2f 00 6d 00 61 00 69 00 6e 00 2f 00 6f 00 75 00 74 00 70 00 75 00 74 00 5f 00 6c 00 2e 00 74 00 78 00 74 00 } //2 raw.githubusercontent.com/Troot0Fobia/TestFile/refs/heads/main/output_l.txt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=14
 
}