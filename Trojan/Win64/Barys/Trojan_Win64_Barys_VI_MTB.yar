
rule Trojan_Win64_Barys_VI_MTB{
	meta:
		description = "Trojan:Win64/Barys.VI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 69 6e 67 20 42 79 70 61 73 73 20 2d 20 41 6e 74 69 63 68 65 61 74 2e 2e } //1 Injecting Bypass - Anticheat..
		$a_01_1 = {48 44 2d 50 6c 61 79 65 72 2e 65 78 65 } //1 HD-Player.exe
		$a_01_2 = {4d 45 6d 75 48 65 61 64 6c 65 73 73 2e 65 78 65 } //1 MEmuHeadless.exe
		$a_01_3 = {4c 64 56 42 6f 78 48 65 61 64 6c 65 73 73 2e 65 78 65 } //1 LdVBoxHeadless.exe
		$a_01_4 = {53 6e 69 70 65 72 20 53 63 6f 70 65 20 3a 20 55 6e 73 75 63 63 65 73 73 66 75 6c 21 } //1 Sniper Scope : Unsuccessful!
		$a_01_5 = {45 6d 75 6c 61 74 6f 72 20 2d 20 42 79 70 61 73 73 3a 20 41 70 70 6c 79 69 6e 67 } //1 Emulator - Bypass: Applying
		$a_01_6 = {68 6f 73 74 3d 25 73 } //1 host=%s
		$a_01_7 = {70 6f 72 74 3d 25 6c 64 } //1 port=%ld
		$a_01_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}