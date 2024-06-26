
rule Trojan_Win32_MpTamperSrvDisableAV_H{
	meta:
		description = "Trojan:Win32/MpTamperSrvDisableAV.H,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 00 74 00 6f 00 70 00 20 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 } //02 00  stop windefend
		$a_00_1 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 } //02 00  delete windefend
		$a_00_2 = {73 00 74 00 6f 00 70 00 20 00 77 00 64 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //02 00  stop wdfilter
		$a_00_3 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 77 00 64 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //02 00  delete wdfilter
		$a_00_4 = {73 00 74 00 6f 00 70 00 20 00 73 00 65 00 6e 00 73 00 65 00 } //02 00  stop sense
		$a_00_5 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 65 00 6e 00 73 00 65 00 } //fe ff  delete sense
		$a_00_6 = {73 00 65 00 6e 00 73 00 65 00 20 00 73 00 68 00 69 00 65 00 6c 00 64 00 } //00 00  sense shield
	condition:
		any of ($a_*)
 
}