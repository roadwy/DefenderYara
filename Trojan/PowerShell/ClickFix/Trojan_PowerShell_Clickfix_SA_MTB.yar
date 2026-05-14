
rule Trojan_PowerShell_Clickfix_SA_MTB{
	meta:
		description = "Trojan:PowerShell/Clickfix.SA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //10 powershell.exe
		$a_00_1 = {3d 00 4a 00 6f 00 69 00 6e 00 2d 00 50 00 61 00 74 00 68 00 20 00 24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //10 =Join-Path $env:TEMP
		$a_00_2 = {47 00 65 00 74 00 52 00 61 00 6e 00 64 00 6f 00 6d 00 46 00 69 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 28 00 29 00 2b 00 27 00 2e 00 65 00 78 00 65 00 27 00 29 00 } //10 GetRandomFileName()+'.exe')
		$a_00_3 = {73 00 72 00 63 00 3d 00 63 00 6c 00 69 00 63 00 6b 00 66 00 69 00 78 00 26 00 } //10 src=clickfix&
		$a_00_4 = {69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 } //10 index.php
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10) >=50
 
}