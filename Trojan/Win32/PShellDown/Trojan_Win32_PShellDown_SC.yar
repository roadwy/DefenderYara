
rule Trojan_Win32_PShellDown_SC{
	meta:
		description = "Trojan:Win32/PShellDown.SC,SIGNATURE_TYPE_CMDHSTR_EXT,1f 00 1f 00 0b 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c } //powershell  10
		$a_80_1 = {68 74 74 70 } //http  10
		$a_80_2 = {6e 65 74 2d 77 65 62 63 6c 69 65 6e 74 } //net-webclient  10
		$a_80_3 = {6d 69 63 72 6f 73 6f 66 74 2e 70 6f 77 65 72 73 68 65 6c 6c 2e 63 6f 6d 6d 61 6e 64 73 2e 77 65 62 72 65 71 75 65 73 74 73 65 73 73 69 6f 6e } //microsoft.powershell.commands.webrequestsession  20
		$a_80_4 = {69 6e 76 6f 6b 65 2d 77 65 62 72 65 71 75 65 73 74 } //invoke-webrequest  10
		$a_80_5 = {64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 } //downloadstring  1
		$a_80_6 = {64 6f 77 6e 6c 6f 61 64 66 69 6c 65 } //downloadfile  1
		$a_80_7 = {69 6e 76 6f 6b 65 2d 65 78 70 72 65 73 73 69 6f 6e } //invoke-expression  1
		$a_80_8 = {69 65 78 20 } //iex   1
		$a_00_9 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 63 00 68 00 65 00 63 00 6b 00 73 00 63 00 72 00 69 00 70 00 74 00 } //-500 function checkscript
		$a_00_10 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 65 00 76 00 2d 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 67 00 61 00 69 00 61 00 63 00 6c 00 6f 00 75 00 64 00 2e 00 6a 00 70 00 6d 00 63 00 68 00 61 00 73 00 65 00 2e 00 6e 00 65 00 74 00 2f 00 61 00 70 00 69 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 76 00 31 00 } //-100 https://dev-shell.gaiacloud.jpmchase.net/api/install/v1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*20+(#a_80_4  & 1)*10+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_00_9  & 1)*-500+(#a_00_10  & 1)*-100) >=31
 
}