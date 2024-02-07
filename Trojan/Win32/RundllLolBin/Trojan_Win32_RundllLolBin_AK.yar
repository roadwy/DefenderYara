
rule Trojan_Win32_RundllLolBin_AK{
	meta:
		description = "Trojan:Win32/RundllLolBin.AK,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  powershell.exe
		$a_00_1 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //01 00  -command
		$a_00_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //01 00  invoke-expression
		$a_00_3 = {69 00 65 00 78 00 } //01 00  iex
		$a_00_4 = {2e 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00  .invoke
		$a_00_5 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}