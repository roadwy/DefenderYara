
rule Trojan_Win32_Goptaju_D{
	meta:
		description = "Trojan:Win32/Goptaju.D,SIGNATURE_TYPE_CMDHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 00 65 00 78 00 } //10 iex
		$a_00_1 = {6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //1 new-object system.net.webclient
		$a_00_2 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //1 .downloadstring(
		$a_00_3 = {2e 00 70 00 73 00 31 00 } //1 .ps1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=13
 
}