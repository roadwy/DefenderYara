
rule HackTool_Win64_ProductKey_G_MSR{
	meta:
		description = "HackTool:Win64/ProductKey.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 73 5c 56 53 32 30 30 35 5c 50 72 6f 64 75 4b 65 79 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 64 75 4b 65 79 2e 70 64 62 } //1 Projects\VS2005\ProduKey\x64\Release\ProduKey.pdb
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4e 69 72 53 6f 66 74 5c 50 72 6f 64 75 4b 65 79 } //1 Software\NirSoft\ProduKey
		$a_01_2 = {75 74 69 6c 73 2f 70 72 6f 64 75 63 74 5f 63 64 5f 6b 65 79 5f 76 69 65 77 65 72 2e 68 74 6d 6c } //1 utils/product_cd_key_viewer.html
		$a_01_3 = {24 24 50 52 4f 44 55 43 4b 45 59 5f 54 45 4d 50 5f 48 49 56 45 24 24 } //1 $$PRODUCKEY_TEMP_HIVE$$
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}