
rule Trojan_Win32_Lazy_NL_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 f9 80 3e 00 75 ec 83 7c 24 ?? 01 75 63 eb 03 8d 49 00 8a 07 88 06 8a 0f 46 47 } //3
		$a_01_1 = {8d 9b 00 00 00 00 57 56 ff d3 85 c0 74 30 8a 06 46 84 c0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Lazy_NL_MTB_2{
	meta:
		description = "Trojan:Win32/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 77 65 68 66 77 65 6f 6a 6f 69 72 } //2 fwehfweojoir
		$a_01_1 = {70 72 65 73 69 64 65 6e 74 73 74 61 74 69 73 74 69 63 70 72 6f } //2 presidentstatisticpro
		$a_01_2 = {4b 55 51 34 50 77 6f 58 62 67 2e 65 78 65 } //2 KUQ4PwoXbg.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_Win32_Lazy_NL_MTB_3{
	meta:
		description = "Trojan:Win32/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 68 79 20 75 20 72 65 76 65 72 73 65 20 6d 79 20 73 74 75 62 3f 28 28 28 } //2 why u reverse my stub?(((
		$a_01_1 = {28 20 69 20 64 6f 6e 74 20 6c 6f 76 65 20 75 2c 20 62 72 6f 28 28 28 } //1 ( i dont love u, bro(((
		$a_01_2 = {4b 69 6c 6c 54 69 6d 65 72 } //1 KillTimer
		$a_01_3 = {3c 20 69 20 6c 6f 76 65 20 75 2c 20 62 72 6f 29 } //1 < i love u, bro)
		$a_01_4 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //1 OpenProcessToken
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}