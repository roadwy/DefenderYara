
rule Trojan_Win32_Qakbot_S_MSR{
	meta:
		description = "Trojan:Win32/Qakbot.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 6d 73 2d 70 6c 61 79 65 72 5c 70 72 30 33 32 5c 62 72 6d 44 73 64 2e 70 64 62 } //1 c:\ms-player\pr032\brmDsd.pdb
		$a_01_1 = {57 31 34 2c 45 52 61 68 61 73 43 68 72 6f 6d 65 } //1 W14,ERahasChrome
		$a_01_2 = {43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 28 00 25 00 66 00 20 00 66 00 69 00 6c 00 65 00 2c 00 20 00 25 00 61 00 20 00 61 00 6b 00 65 00 6c 00 70 00 61 00 64 00 20 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 29 00 } //1 Command (%f file, %a akelpad directory)
		$a_01_3 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 63 00 68 00 65 00 63 00 6b 00 62 00 6f 00 78 00 20 00 66 00 6f 00 72 00 20 00 70 00 6c 00 75 00 67 00 69 00 6e 00 20 00 61 00 75 00 74 00 6f 00 6c 00 6f 00 61 00 64 00 } //1 Select checkbox for plugin autoload
		$a_01_4 = {79 69 6e 64 65 70 65 6e 64 65 6e 74 61 6c 73 6f 66 6f 72 55 69 64 69 67 69 74 61 6c } //1 yindependentalsoforUidigital
		$a_01_5 = {44 65 6c 65 74 65 50 72 69 6e 74 65 72 44 72 69 76 65 72 45 78 57 } //1 DeletePrinterDriverExW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}