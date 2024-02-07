
rule Trojan_Win32_Adload_HNU_MTB{
	meta:
		description = "Trojan:Win32/Adload.HNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 48 04 89 01 c7 80 ec ff 13 00 02 00 00 00 b9 90 01 04 29 f1 89 0d 90 01 04 ba 90 01 04 29 f2 8d 0c 02 89 0d 90 01 04 83 ce 02 89 74 02 fc eb 0c c7 05 d8 4c 42 01 00 00 00 00 31 c9 89 c8 83 c4 90 01 01 5e c3 90 00 } //01 00 
		$a_01_1 = {4b 69 6c 6c 54 69 6d 65 72 } //01 00  KillTimer
		$a_01_2 = {6b 4c 6f 61 64 65 72 4c 6f 63 6b } //01 00  kLoaderLock
		$a_80_3 = {66 79 43 68 61 6e 67 65 4b 65 79 } //fyChangeKey  00 00 
	condition:
		any of ($a_*)
 
}