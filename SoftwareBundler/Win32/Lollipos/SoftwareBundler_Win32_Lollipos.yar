
rule SoftwareBundler_Win32_Lollipos{
	meta:
		description = "SoftwareBundler:Win32/Lollipos,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {46 00 72 00 6d 00 5f 00 4c 00 6f 00 6c 00 6c 00 69 00 70 00 6f 00 70 00 90 1c 01 00 00 90 1c 01 00 00 00 00 90 00 } //02 00 
		$a_01_1 = {75 46 72 6d 54 42 5f 4c 6f 6c 6c 69 70 6f 70 } //01 00  uFrmTB_Lollipop
		$a_01_2 = {6c 6f 6c 6c 69 70 6f 70 2d 6e 65 74 77 6f 72 6b 2e 63 6f 6d 2f } //00 00  lollipop-network.com/
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}