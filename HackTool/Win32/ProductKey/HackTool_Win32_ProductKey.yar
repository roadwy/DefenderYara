
rule HackTool_Win32_ProductKey{
	meta:
		description = "HackTool:Win32/ProductKey,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 74 69 6c 73 2f 70 72 6f 64 75 63 74 5f 63 64 5f 6b 65 79 5f 76 69 65 77 65 72 2e 68 74 6d 6c } //01 00  utils/product_cd_key_viewer.html
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4e 69 72 53 6f 66 74 5c 50 72 6f 64 75 4b 65 79 } //01 00  Software\NirSoft\ProduKey
		$a_01_2 = {53 6f 66 74 77 61 72 65 4b 65 79 46 69 6c 65 } //01 00  SoftwareKeyFile
		$a_01_3 = {45 78 74 72 61 63 74 57 4d 49 50 61 72 74 69 61 6c 4b 65 79 } //01 00  ExtractWMIPartialKey
		$a_01_4 = {44 69 67 69 74 61 6c 50 72 6f 64 75 63 74 49 44 } //00 00  DigitalProductID
	condition:
		any of ($a_*)
 
}