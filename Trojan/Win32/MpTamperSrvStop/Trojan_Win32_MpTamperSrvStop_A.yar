
rule Trojan_Win32_MpTamperSrvStop_A{
	meta:
		description = "Trojan:Win32/MpTamperSrvStop.A,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 6e 00 73 00 65 00 } //1 sense
		$a_00_1 = {77 00 64 00 6e 00 69 00 73 00 73 00 76 00 63 00 } //1 wdnissvc
		$a_00_2 = {77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 } //1 windefend
		$a_00_3 = {2d 00 64 00 63 00 73 00 76 00 63 00 } //10 -dcsvc
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10) >=11
 
}