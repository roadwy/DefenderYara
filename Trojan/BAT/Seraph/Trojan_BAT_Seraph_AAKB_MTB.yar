
rule Trojan_BAT_Seraph_AAKB_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 17 73 90 01 01 00 00 0a 0d 02 28 90 01 01 00 00 06 75 90 01 01 00 00 1b 13 04 09 11 04 16 11 04 8e 69 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 13 05 dd 90 01 01 00 00 00 09 39 90 01 01 00 00 00 09 6f 90 01 01 00 00 0a dc 90 00 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}