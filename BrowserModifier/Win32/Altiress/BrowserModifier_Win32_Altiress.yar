
rule BrowserModifier_Win32_Altiress{
	meta:
		description = "BrowserModifier:Win32/Altiress,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 00 65 00 76 00 65 00 6e 00 74 00 3d 00 65 00 78 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 73 00 74 00 61 00 72 00 74 00 } //01 00  &event=ex_update_start
		$a_01_1 = {26 00 65 00 76 00 65 00 6e 00 74 00 3d 00 65 00 78 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5f 00 73 00 74 00 61 00 72 00 74 00 } //01 00  &event=ex_install_start
		$a_01_2 = {45 00 78 00 70 00 72 00 65 00 73 00 73 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 } //01 00  Express Software
		$a_01_3 = {4d 00 61 00 69 00 6e 00 00 00 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}