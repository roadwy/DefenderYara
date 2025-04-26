
rule Trojan_Win32_RundllLolBin_AF{
	meta:
		description = "Trojan:Win32/RundllLolBin.AF,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {6c 00 73 00 61 00 73 00 73 00 } //1 lsass
		$a_00_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } //1 rundll32
		$a_00_3 = {4d 00 69 00 6e 00 69 00 44 00 75 00 6d 00 70 00 } //1 MiniDump
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}