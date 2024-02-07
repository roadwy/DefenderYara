
rule Trojan_Win32_Pawntilla_A{
	meta:
		description = "Trojan:Win32/Pawntilla.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 67 6f 74 50 77 6e 65 64 42 79 57 31 4e 74 33 52 } //01 00  UgotPwnedByW1Nt3R
		$a_01_1 = {53 63 68 77 34 72 7a } //01 00  Schw4rz
		$a_01_2 = {54 42 6f 74 43 6f 6e 66 69 67 2c } //01 00  TBotConfig,
		$a_01_3 = {5c 6b 2d 6d 65 6c 65 6f 6e 2e 65 78 65 } //01 00  \k-meleon.exe
		$a_01_4 = {70 69 6e 67 20 2d 6e 20 31 20 6c 6f 63 61 6c 68 6f 73 74 } //01 00  ping -n 1 localhost
		$a_01_5 = {53 69 6c 2e 62 61 74 } //00 00  Sil.bat
		$a_00_6 = {5d 04 00 } //00 0e 
	condition:
		any of ($a_*)
 
}