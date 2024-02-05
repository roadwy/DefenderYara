
rule Trojan_Win32_Dexphot_CD{
	meta:
		description = "Trojan:Win32/Dexphot.CD,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 20 2d 00 69 00 90 02 10 68 00 74 00 74 00 70 00 90 00 } //01 00 
		$a_02_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 20 2f 00 69 00 90 02 10 68 00 74 00 74 00 70 00 90 00 } //f6 ff 
		$a_80_2 = {77 77 77 2e 7a 6f 6f 6d 2e 75 73 } //www.zoom.us  f6 ff 
		$a_80_3 = {70 6f 77 65 72 73 68 65 6c 6c } //powershell  00 00 
	condition:
		any of ($a_*)
 
}