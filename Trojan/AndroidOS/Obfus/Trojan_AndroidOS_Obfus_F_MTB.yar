
rule Trojan_AndroidOS_Obfus_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Obfus.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 7c 01 ad 07 7e 01 af 48 0e 0e 0f 07 4f 02 10 0a 00 02 11 09 00 94 10 10 11 74 02 2e 00 0f 00 0a 0f b7 fe 8d ee 4f 0e 0c 0d } //1
		$a_03_1 = {6e 70 2f 6d 61 6e 61 67 65 72 2f [0-03] 63 6b 53 69 67 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}