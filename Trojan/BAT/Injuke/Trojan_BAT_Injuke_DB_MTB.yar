
rule Trojan_BAT_Injuke_DB_MTB{
	meta:
		description = "Trojan:BAT/Injuke.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 00 11 02 11 00 8e 69 5d 91 7e 90 01 01 00 00 04 11 02 91 61 d2 6f 90 01 01 00 00 0a 38 90 02 04 11 01 6f 90 01 01 00 00 0a 2a 73 90 01 01 00 00 0a 13 01 38 90 02 04 16 13 02 38 90 00 } //3
		$a_01_1 = {58 00 65 00 65 00 66 00 68 00 70 00 6a 00 62 00 73 00 61 00 7a 00 61 00 70 00 79 00 69 00 61 00 68 00 61 00 6a 00 } //1 Xeefhpjbsazapyiahaj
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}