
rule Trojan_Win32_Adload_DKL_MTB{
	meta:
		description = "Trojan:Win32/Adload.DKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 0d cc 5c 42 01 c7 00 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 48 04 89 01 c7 80 ec ff 13 00 02 00 00 00 b9 ?? ?? ?? ?? 29 f1 89 ?? ?? ?? ?? 01 ba f0 ff 13 00 29 f2 8d 0c 02 89 0d dc 5c 42 01 83 ce 02 89 74 02 fc eb 0c c7 05 d8 5c 42 01 00 00 00 00 31 c9 89 c8 83 c4 10 5e c3 } //10
		$a_02_1 = {8b d1 c1 e9 03 0f b6 d6 b8 01 00 00 00 d3 e0 09 04 95 ?? ?? ?? ?? b8 01 00 00 00 8b ca d3 e0 09 05 ?? ?? ?? ?? c3 } //10
		$a_80_2 = {50 75 72 61 6e 20 46 69 6c 65 20 52 65 63 6f 76 65 72 79 2e 65 78 65 } //Puran File Recovery.exe  1
		$a_80_3 = {4b 69 6c 6c 54 69 6d 65 72 } //KillTimer  1
		$a_80_4 = {6b 4c 6f 61 64 65 72 4c 6f 63 6b } //kLoaderLock  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=23
 
}