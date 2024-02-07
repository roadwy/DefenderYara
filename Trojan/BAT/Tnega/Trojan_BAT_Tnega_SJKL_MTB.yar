
rule Trojan_BAT_Tnega_SJKL_MTB{
	meta:
		description = "Trojan:BAT/Tnega.SJKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {71 75 61 6e 6c 79 6b 68 6f 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  quanlykho.Properties
		$a_81_1 = {64 61 6e 67 6e 68 61 70 } //01 00  dangnhap
		$a_81_2 = {42 69 74 6d 61 70 } //01 00  Bitmap
		$a_81_3 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_81_4 = {52 65 76 65 72 73 65 53 74 72 69 6e 67 } //01 00  ReverseString
		$a_81_5 = {42 69 6e 64 69 6e 67 46 6c 61 67 73 } //01 00  BindingFlags
		$a_81_6 = {49 6e 69 74 69 61 6c 69 7a 65 43 6f 6d 70 6f 6e 65 6e 74 } //01 00  InitializeComponent
		$a_81_7 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}