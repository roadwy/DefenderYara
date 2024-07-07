
rule Trojan_BAT_Formbook_AD_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_1 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 } //1 GetProcessesByName
		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_4 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_01_5 = {4b 69 6c 6c } //1 Kill
		$a_01_6 = {6d 00 65 00 74 00 61 00 6c 00 73 00 68 00 6f 00 6f 00 70 00 70 00 2e 00 30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 31 00 31 00 2e 00 65 00 78 00 65 00 } //1 metalshoopp.000webhostapp.com/WindowsFormsApp11.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}