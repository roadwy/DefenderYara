
rule Trojan_Win32_MpTamperSrvDisableAV_G{
	meta:
		description = "Trojan:Win32/MpTamperSrvDisableAV.G,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 } //02 00  delete windefend
		$a_00_1 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 77 00 64 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //02 00  delete wdfilter
		$a_00_2 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 65 00 6e 00 73 00 65 00 } //02 00  delete sense
		$a_00_3 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 64 00 69 00 61 00 67 00 74 00 72 00 61 00 63 00 6b 00 } //fe ff  delete diagtrack
		$a_00_4 = {73 00 65 00 6e 00 73 00 65 00 20 00 73 00 68 00 69 00 65 00 6c 00 64 00 } //01 00  sense shield
		$a_00_5 = {75 00 3a 00 74 00 } //01 00  u:t
		$a_00_6 = {75 00 3d 00 74 00 } //00 00  u=t
	condition:
		any of ($a_*)
 
}