
rule Trojan_AndroidOS_Xloader_I1{
	meta:
		description = "Trojan:AndroidOS/Xloader.I1,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 75 2e 53 4f 47 4f 55 } //01 00  com.u.SOGOU
		$a_00_1 = {4c 72 65 6e 2f 5a 48 41 4e } //01 00  Lren/ZHAN
		$a_00_2 = {4c 63 6f 69 2f 51 55 58 49 } //00 00  Lcoi/QUXI
	condition:
		any of ($a_*)
 
}