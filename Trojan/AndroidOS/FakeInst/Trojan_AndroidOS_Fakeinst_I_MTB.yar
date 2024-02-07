
rule Trojan_AndroidOS_Fakeinst_I_MTB{
	meta:
		description = "Trojan:AndroidOS/Fakeinst.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 73 55 6b 72 61 69 6e 65 49 44 } //01 00  isUkraineID
		$a_01_1 = {67 65 74 41 70 70 4e 61 6d 65 } //01 00  getAppName
		$a_01_2 = {69 73 4b 5a 49 44 } //01 00  isKZID
		$a_01_3 = {63 6f 6d 2f 64 65 63 72 79 70 74 73 74 72 69 6e 67 6d 61 6e 61 67 65 72 } //01 00  com/decryptstringmanager
		$a_01_4 = {73 74 61 72 74 41 63 74 69 76 61 74 65 } //00 00  startActivate
	condition:
		any of ($a_*)
 
}