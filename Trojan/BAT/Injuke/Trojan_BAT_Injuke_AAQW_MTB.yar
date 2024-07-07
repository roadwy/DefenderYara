
rule Trojan_BAT_Injuke_AAQW_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AAQW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 16 73 90 01 01 00 00 0a 13 09 20 00 00 00 00 7e 90 01 01 00 00 04 7b 90 01 01 00 00 04 39 90 01 01 ff ff ff 26 20 00 00 00 00 38 90 01 01 ff ff ff 11 01 16 28 90 01 01 00 00 0a 13 02 90 00 } //3
		$a_01_1 = {11 0b 28 01 00 00 2b 28 02 00 00 2b 28 16 00 00 0a 13 05 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}