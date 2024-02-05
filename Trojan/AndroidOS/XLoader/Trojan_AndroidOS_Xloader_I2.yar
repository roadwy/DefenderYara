
rule Trojan_AndroidOS_Xloader_I2{
	meta:
		description = "Trojan:AndroidOS/Xloader.I2,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 4c 6f 61 64 65 72 } //01 00 
		$a_01_1 = {63 63 61 64 64 46 6c 61 67 73 } //01 00 
		$a_01_2 = {31 62 70 74 6c 6a 30 } //00 00 
	condition:
		any of ($a_*)
 
}