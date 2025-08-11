
rule Trojan_Win32_ClickFix_DDQ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6e 00 6e 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {29 00 7c 00 25 00 7b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 24 00 5f 00 7d 00 29 00 2d 00 6a 00 6f 00 69 00 6e 00 } //10 )|%{[char]$_})-join
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10) >=110
 
}
rule Trojan_Win32_ClickFix_DDQ_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.DDQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {49 00 4f 00 2e 00 46 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 24 00 } //1 IO.File]::Create($
		$a_00_1 = {5b 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 } //1 [Net.WebRequest]::Create
		$a_00_2 = {2e 00 43 00 6f 00 70 00 79 00 54 00 6f 00 28 00 24 00 } //1 .CopyTo($
		$a_00_3 = {4a 00 6f 00 69 00 6e 00 2d 00 50 00 61 00 74 00 68 00 20 00 24 00 } //1 Join-Path $
		$a_00_4 = {72 65 70 6c 61 63 65 } //1 replace
		$a_00_5 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 Start-Process
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}