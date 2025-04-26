
rule Trojan_Win64_Cryptinject_QC_MTB{
	meta:
		description = "Trojan:Win64/Cryptinject.QC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 54 45 4d 50 2f 71 73 78 62 6b 78 2e 65 78 65 } //1 C:\TEMP/qsxbkx.exe
		$a_81_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 72 75 6e 64 6c 6c } //1 rundll32.exe %s,rundll
		$a_81_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 43 6f 6d 6d 61 6e 64 } //1 powershell.exe -Command
		$a_81_3 = {67 73 6a 73 6f 69 67 2e 6c 6e 6b } //1 gsjsoig.lnk
		$a_81_4 = {24 57 73 68 53 68 65 6c 6c 2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 24 73 68 6f 72 74 63 75 74 50 61 74 68 29 } //1 $WshShell.CreateShortcut($shortcutPath)
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}