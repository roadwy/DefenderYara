
rule Trojan_Win32_PShellDlr_SF_MTB{
	meta:
		description = "Trojan:Win32/PShellDlr.SF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,1b 04 1b 04 0d 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //500 powershell
		$a_00_1 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //500 net.webclient
		$a_00_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 } //50 invoke
		$a_00_3 = {43 00 72 00 65 00 61 00 74 00 65 00 28 00 29 00 2e 00 41 00 64 00 64 00 53 00 63 00 72 00 69 00 70 00 74 00 28 00 } //50 Create().AddScript(
		$a_00_4 = {20 00 69 00 77 00 72 00 } //50  iwr
		$a_00_5 = {2e 00 73 00 68 00 6f 00 70 00 } //1 .shop
		$a_00_6 = {2e 00 78 00 79 00 7a 00 } //1 .xyz
		$a_00_7 = {2e 00 63 00 79 00 6f 00 75 00 } //1 .cyou
		$a_00_8 = {2e 00 63 00 6c 00 69 00 63 00 6b 00 } //1 .click
		$a_00_9 = {2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 } //1 .online
		$a_00_10 = {2e 00 74 00 6f 00 64 00 61 00 79 00 } //1 .today
		$a_00_11 = {2e 00 6c 00 61 00 74 00 } //1 .lat
		$a_00_12 = {2e 00 69 00 63 00 75 00 } //1 .icu
	condition:
		((#a_00_0  & 1)*500+(#a_00_1  & 1)*500+(#a_00_2  & 1)*50+(#a_00_3  & 1)*50+(#a_00_4  & 1)*50+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=1051
 
}