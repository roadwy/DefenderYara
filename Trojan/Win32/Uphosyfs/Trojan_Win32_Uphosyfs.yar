
rule Trojan_Win32_Uphosyfs{
	meta:
		description = "Trojan:Win32/Uphosyfs,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 46 00 6f 00 6c 00 64 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //01 00  IFolder.dll
		$a_01_1 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //01 00  system32.exe
		$a_01_2 = {49 00 52 00 4d 00 2e 00 65 00 78 00 65 00 } //01 00  IRM.exe
		$a_01_3 = {4d 00 79 00 5f 00 4d 00 75 00 73 00 69 00 63 00 2e 00 65 00 78 00 65 00 } //01 00  My_Music.exe
		$a_01_4 = {50 00 68 00 6f 00 74 00 6f 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  Photos.exe
		$a_01_5 = {55 00 70 00 46 00 69 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  UpFile.exe
		$a_01_6 = {53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //00 00  System32.exe
	condition:
		any of ($a_*)
 
}