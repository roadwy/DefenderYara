
rule Trojan_BAT_Redline_GDI_MTB{
	meta:
		description = "Trojan:BAT/Redline.GDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 66 73 64 6b 66 64 68 67 66 73 68 73 65 66 66 64 66 61 66 66 68 66 64 63 68 } //01 00  hfsdkfdhgfshseffdfaffhfdch
		$a_01_1 = {66 63 68 66 68 66 64 67 66 61 64 66 64 66 72 73 66 73 73 68 64 6b 66 66 66 67 68 } //01 00  fchfhfdgfadfdfrsfsshdkfffgh
		$a_01_2 = {68 6b 67 66 73 66 64 66 66 64 68 66 68 64 64 72 66 61 68 68 64 64 73 73 68 63 66 } //01 00  hkgfsfdffdhfhddrfahhddsshcf
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}