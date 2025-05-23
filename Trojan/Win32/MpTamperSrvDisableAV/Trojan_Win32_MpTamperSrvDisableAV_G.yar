
rule Trojan_Win32_MpTamperSrvDisableAV_G{
	meta:
		description = "Trojan:Win32/MpTamperSrvDisableAV.G,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_00_0 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 } //2 delete windefend
		$a_00_1 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 77 00 64 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //2 delete wdfilter
		$a_00_2 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 65 00 6e 00 73 00 65 00 } //2 delete sense
		$a_00_3 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 64 00 69 00 61 00 67 00 74 00 72 00 61 00 63 00 6b 00 } //2 delete diagtrack
		$a_00_4 = {73 00 65 00 6e 00 73 00 65 00 20 00 73 00 68 00 69 00 65 00 6c 00 64 00 } //-2 sense shield
		$a_00_5 = {75 00 3a 00 74 00 } //1 u:t
		$a_00_6 = {75 00 3d 00 74 00 } //1 u=t
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*-2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=3
 
}