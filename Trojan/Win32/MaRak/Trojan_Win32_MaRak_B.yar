
rule Trojan_Win32_MaRak_B{
	meta:
		description = "Trojan:Win32/MaRak.B,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {5b 00 69 00 6f 00 2e 00 66 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 72 00 65 00 61 00 64 00 61 00 6c 00 6c 00 74 00 65 00 78 00 74 00 28 00 } //1 [io.file]::readalltext(
		$a_00_2 = {2e 00 63 00 6d 00 64 00 27 00 29 00 20 00 2d 00 73 00 70 00 6c 00 69 00 74 00 } //1 .cmd') -split
		$a_00_3 = {3b 00 69 00 65 00 78 00 20 00 28 00 24 00 } //1 ;iex ($
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}