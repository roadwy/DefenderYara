
rule Trojan_Win32_RundllLolBin_AJ{
	meta:
		description = "Trojan:Win32/RundllLolBin.AJ,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 -command
		$a_00_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //1 invoke-expression
		$a_00_3 = {69 00 65 00 78 00 } //1 iex
		$a_00_4 = {2e 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 .invoke
		$a_00_5 = {73 00 65 00 6e 00 74 00 69 00 6e 00 65 00 6c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //-1 sentinelCommand
		$a_00_6 = {63 00 75 00 73 00 74 00 6f 00 6d 00 73 00 63 00 72 00 69 00 70 00 74 00 68 00 61 00 6e 00 64 00 6c 00 65 00 72 00 } //-1 customscripthandler
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*-1+(#a_00_6  & 1)*-1) >=4
 
}