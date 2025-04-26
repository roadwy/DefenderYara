
rule TrojanDownloader_Win32_PSWebtoos_A{
	meta:
		description = "TrojanDownloader:Win32/PSWebtoos.A,SIGNATURE_TYPE_CMDHSTR_EXT,20 00 20 00 08 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c } //powershell  10
		$a_80_1 = {68 74 74 70 } //http  10
		$a_80_2 = {6e 65 74 2d 77 65 62 63 6c 69 65 6e 74 } //net-webclient  10
		$a_80_3 = {64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 } //downloadstring  1
		$a_80_4 = {64 6f 77 6e 6c 6f 61 64 66 69 6c 65 } //downloadfile  1
		$a_80_5 = {73 74 61 72 74 2d 70 72 6f 63 65 73 73 } //start-process  1
		$a_00_6 = {69 00 65 00 78 00 } //1 iex
		$a_80_7 = {69 6e 76 6f 6b 65 2d 65 78 70 72 65 73 73 69 6f 6e } //invoke-expression  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_00_6  & 1)*1+(#a_80_7  & 1)*1) >=32
 
}