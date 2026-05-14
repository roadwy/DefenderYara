
rule Trojan_Win32_Goptaju_B{
	meta:
		description = "Trojan:Win32/Goptaju.B,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 72 00 65 00 73 00 74 00 6d 00 65 00 74 00 68 00 6f 00 64 00 } //1 invoke-restmethod
		$a_00_1 = {69 00 65 00 78 00 } //1 iex
		$a_00_2 = {2d 00 75 00 72 00 69 00 } //1 -uri
		$a_00_3 = {29 00 2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 } //1 ).replace(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}