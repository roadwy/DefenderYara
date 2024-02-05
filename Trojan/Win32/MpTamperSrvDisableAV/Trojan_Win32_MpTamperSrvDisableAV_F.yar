
rule Trojan_Win32_MpTamperSrvDisableAV_F{
	meta:
		description = "Trojan:Win32/MpTamperSrvDisableAV.F,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 04 00 04 00 00 04 00 "
		
	strings :
		$a_02_0 = {63 00 6f 00 6e 00 66 00 69 00 67 00 90 02 06 74 00 72 00 75 00 73 00 74 00 65 00 64 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 90 02 06 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 90 00 } //01 00 
		$a_02_1 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 90 02 ff 73 00 65 00 6e 00 73 00 65 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 90 00 } //01 00 
		$a_02_2 = {69 00 63 00 61 00 63 00 6c 00 73 00 90 02 ff 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 90 00 } //01 00 
		$a_02_3 = {69 00 63 00 61 00 63 00 6c 00 73 00 90 02 ff 73 00 6d 00 61 00 72 00 74 00 73 00 63 00 72 00 65 00 65 00 6e 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}