
rule Trojan_BAT_Seraph_G_MTB{
	meta:
		description = "Trojan:BAT/Seraph.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 6f 6e 73 6f 6c 65 41 70 70 90 02 04 2e 65 78 65 90 00 } //01 00 
		$a_81_1 = {54 65 73 74 2d 43 6f 6e 6e 65 63 74 69 6f 6e 20 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00  Test-Connection www.google.com
		$a_81_2 = {49 6d 61 67 65 73 2e 70 6e 67 } //01 00  Images.png
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {67 65 74 5f 50 69 78 65 6c 46 6f 72 6d 61 74 } //01 00  get_PixelFormat
		$a_81_5 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_81_6 = {43 6f 6e 76 65 72 74 } //00 00  Convert
	condition:
		any of ($a_*)
 
}