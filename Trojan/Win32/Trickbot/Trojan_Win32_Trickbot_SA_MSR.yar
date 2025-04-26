
rule Trojan_Win32_Trickbot_SA_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 6f 61 64 53 68 65 6c 6c 43 6f 64 65 } //1 LoadShellCode
		$a_01_1 = {47 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 39 00 31 00 31 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 63 00 42 00 75 00 74 00 74 00 6f 00 6e 00 42 00 61 00 72 00 5c 00 63 00 42 00 75 00 74 00 74 00 6f 00 6e 00 42 00 61 00 72 00 5c 00 42 00 75 00 74 00 74 00 6f 00 6e 00 42 00 61 00 72 00 2e 00 76 00 62 00 70 00 } //1 G*\AC:\Users\911\Desktop\cButtonBar\cButtonBar\ButtonBar.vbp
		$a_00_2 = {70 53 68 65 6c 6c 43 6f 64 65 } //1 pShellCode
		$a_00_3 = {49 6e 69 74 53 68 65 6c 6c 43 6f 64 65 } //1 InitShellCode
		$a_00_4 = {43 41 5a 78 47 45 55 33 34 4f 43 46 42 42 4b 43 51 4a 68 57 55 45 23 24 5f 53 56 52 52 5b 53 51 5a 78 } //1 CAZxGEU34OCFBBKCQJhWUE#$_SVRR[SQZx
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Trickbot_SA_MSR_2{
	meta:
		description = "Trojan:Win32/Trickbot.SA!MSR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 00 3a 00 5c 00 43 00 75 00 73 00 74 00 6f 00 6d 00 5c 00 44 00 61 00 72 00 69 00 6e 00 73 00 31 00 2e 00 76 00 62 00 70 00 } //1 F:\Custom\Darins1.vbp
		$a_01_1 = {5c 00 69 00 6e 00 64 00 69 00 61 00 6e 00 61 00 5f 00 6a 00 6f 00 6e 00 65 00 73 00 5f 00 61 00 72 00 74 00 5f 00 68 00 61 00 72 00 72 00 69 00 73 00 6f 00 6e 00 5f 00 66 00 6f 00 72 00 64 00 2e 00 6a 00 70 00 67 00 } //1 \indiana_jones_art_harrison_ford.jpg
		$a_01_2 = {4e 00 50 00 5a 00 20 00 4f 00 70 00 74 00 69 00 63 00 73 00 20 00 53 00 74 00 61 00 74 00 65 00 20 00 50 00 6c 00 61 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 NPZ Optics State Plant.exe
		$a_01_3 = {53 00 48 00 45 00 4c 00 4c 00 44 00 4c 00 4c 00 5f 00 44 00 65 00 66 00 56 00 69 00 65 00 77 00 } //1 SHELLDLL_DefView
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}