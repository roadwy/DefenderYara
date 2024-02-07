
rule Trojan_Win32_MpTamperSrvStop_A{
	meta:
		description = "Trojan:Win32/MpTamperSrvStop.A,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 6e 00 73 00 65 00 } //01 00  sense
		$a_00_1 = {77 00 64 00 6e 00 69 00 73 00 73 00 76 00 63 00 } //01 00  wdnissvc
		$a_00_2 = {77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 } //0a 00  windefend
		$a_00_3 = {2d 00 64 00 63 00 73 00 76 00 63 00 } //00 00  -dcsvc
	condition:
		any of ($a_*)
 
}