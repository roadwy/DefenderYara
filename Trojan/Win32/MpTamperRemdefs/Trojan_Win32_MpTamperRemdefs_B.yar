
rule Trojan_Win32_MpTamperRemdefs_B{
	meta:
		description = "Trojan:Win32/MpTamperRemdefs.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 00 70 00 63 00 6d 00 64 00 72 00 75 00 6e 00 } //01 00  mpcmdrun
		$a_00_1 = {2d 00 72 00 65 00 6d 00 6f 00 76 00 65 00 64 00 65 00 66 00 69 00 6e 00 69 00 74 00 69 00 6f 00 6e 00 73 00 20 00 2d 00 61 00 6c 00 6c 00 } //00 00  -removedefinitions -all
	condition:
		any of ($a_*)
 
}