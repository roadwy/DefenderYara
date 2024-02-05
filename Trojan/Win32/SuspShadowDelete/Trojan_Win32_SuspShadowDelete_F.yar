
rule Trojan_Win32_SuspShadowDelete_F{
	meta:
		description = "Trojan:Win32/SuspShadowDelete.F,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 90 02 f0 64 00 65 00 6c 00 65 00 74 00 65 00 90 00 } //01 00 
		$a_02_1 = {77 00 69 00 6e 00 33 00 32 00 5f 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 90 02 f0 72 00 65 00 6d 00 6f 00 76 00 65 00 2d 00 90 00 } //fb ff 
		$a_00_2 = {2e 00 63 00 72 00 65 00 61 00 74 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}