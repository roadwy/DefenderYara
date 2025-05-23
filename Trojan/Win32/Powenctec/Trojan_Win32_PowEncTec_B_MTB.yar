
rule Trojan_Win32_PowEncTec_B_MTB{
	meta:
		description = "Trojan:Win32/PowEncTec.B!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {5b 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 66 00 72 00 6f 00 6d 00 62 00 61 00 73 00 65 00 36 00 34 00 73 00 74 00 72 00 69 00 6e 00 67 00 } //1 [convert]::frombase64string
		$a_00_2 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
		$a_00_3 = {7c 00 20 00 69 00 65 00 78 00 } //1 | iex
		$a_00_4 = {68 00 74 00 74 00 70 00 } //-100 http
		$a_00_5 = {69 00 77 00 72 00 } //-100 iwr
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*-100+(#a_00_5  & 1)*-100) >=4
 
}