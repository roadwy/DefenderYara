
rule Trojan_Win32_SuspStartupInstall_ZPD{
	meta:
		description = "Trojan:Win32/SuspStartupInstall.ZPD,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 } //1 schtasks
		$a_00_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 /create
		$a_00_2 = {20 00 2f 00 46 00 20 00 } //1  /F 
		$a_00_3 = {20 00 2f 00 74 00 6e 00 20 00 } //1  /tn 
		$a_00_4 = {20 00 2f 00 74 00 72 00 20 00 } //1  /tr 
		$a_00_5 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_6 = {2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 -Command
		$a_00_7 = {20 00 69 00 65 00 78 00 } //1  iex
		$a_00_8 = {47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 2d 00 50 00 61 00 74 00 68 00 } //1 Get-ItemProperty -Path
		$a_00_9 = {3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 :FromBase64String
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}