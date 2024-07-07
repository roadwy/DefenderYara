
rule Trojan_AndroidOS_Xloader_I2{
	meta:
		description = "Trojan:AndroidOS/Xloader.I2,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 4c 6f 61 64 65 72 } //1 lLoader
		$a_01_1 = {63 63 61 64 64 46 6c 61 67 73 } //1 ccaddFlags
		$a_01_2 = {31 62 70 74 6c 6a 30 } //1 1bptlj0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}