
rule Trojan_Win32_Capfetox_A{
	meta:
		description = "Trojan:Win32/Capfetox.A,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {69 00 65 00 78 00 } //1 iex
		$a_00_2 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //1 downloadstring(
		$a_00_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 28 00 } //1 downloadfile(
		$a_00_4 = {20 00 2d 00 65 00 6e 00 63 00 } //1  -enc
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=101
 
}