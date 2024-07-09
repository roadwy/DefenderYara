
rule Trojan_AndroidOS_Obfus_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Obfus.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 25 58 00 08 04 25 00 07 40 07 03 71 10 1c 00 03 00 0c 03 07 30 14 0a 0f a3 35 03 28 01 14 0c fe 9a 00 00 97 0a 0a 0c 2c 0a 0c 00 00 00 } //1
		$a_03_1 = {6e 70 2f 6d 61 6e 61 67 65 72 2f [0-03] 63 6b 53 69 67 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}