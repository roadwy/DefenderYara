
rule Trojan_Win32_Priteshel_B{
	meta:
		description = "Trojan:Win32/Priteshel.B,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //2 powershell
		$a_00_1 = {2d 00 65 00 6e 00 63 00 } //2 -enc
		$a_00_2 = {62 00 79 00 70 00 61 00 73 00 73 00 } //1 bypass
		$a_00_3 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}