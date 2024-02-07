
rule Trojan_Win32_MpUtilAbuse_A{
	meta:
		description = "Trojan:Win32/MpUtilAbuse.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 00 70 00 63 00 6d 00 64 00 72 00 75 00 6e 00 } //01 00  mpcmdrun
		$a_00_1 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 20 00 } //01 00  downloadfile 
		$a_00_2 = {75 00 72 00 6c 00 20 00 } //01 00  url 
		$a_00_3 = {70 00 61 00 74 00 68 00 20 00 } //00 00  path 
	condition:
		any of ($a_*)
 
}