
rule Trojan_Win32_PsObfus_Z_MTB{
	meta:
		description = "Trojan:Win32/PsObfus.Z!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {5d 00 20 00 24 00 5f 00 2d 00 41 00 73 00 5b 00 63 00 48 00 61 00 72 00 5d 00 } //1 ] $_-As[cHar]
		$a_00_2 = {6a 00 6f 00 69 00 6e 00 } //1 join
		$a_00_3 = {66 00 6f 00 72 00 65 00 61 00 63 00 68 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 } //1 foreach-object
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}