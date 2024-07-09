
rule Trojan_Win32_QakBot_BA_MTB{
	meta:
		description = "Trojan:Win32/QakBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0f 88 01 41 83 ea ?? 75 f5 } //1
		$a_03_1 = {8b c1 83 e0 ?? 8a 44 10 ?? 30 04 31 41 3b cf 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_QakBot_BA_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 03 1d [0-04] 6a 00 e8 [0-04] 2b d8 a1 [0-04] 33 18 89 1d [0-04] 6a 00 e8 [0-04] 03 05 [0-04] 8b 15 [0-04] 89 02 a1 [0-04] 83 c0 04 a3 [0-04] 33 c0 a3 [0-04] a1 [0-04] 83 c0 04 03 05 [0-04] a3 [0-04] a1 [0-04] 3b 05 [0-04] 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_QakBot_BA_MTB_3{
	meta:
		description = "Trojan:Win32/QakBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 33 7a 49 73 62 52 34 75 64 41 } //3 C3zIsbR4udA
		$a_01_1 = {43 43 36 50 73 46 } //3 CC6PsF
		$a_01_2 = {43 62 4a 56 79 51 30 39 38 76 64 } //3 CbJVyQ098vd
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //3 DllRegisterServer
		$a_01_4 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 } //3 GetCommandLineA
		$a_01_5 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 } //3 FindFirstFileExW
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}