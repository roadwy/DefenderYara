
rule Trojan_BAT_DCRat_MAAB_MTB{
	meta:
		description = "Trojan:BAT/DCRat.MAAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 64 31 63 63 32 62 61 64 2d 64 36 66 37 2d 34 37 62 38 2d 61 66 61 38 2d 33 61 39 64 34 34 33 30 64 63 63 31 } //10 $d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1
		$a_01_1 = {57 9d 02 3c 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 5a 00 00 } //10
		$a_01_2 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 ConfusedByAttribute
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {41 65 73 4d 61 6e 61 67 65 64 } //1 AesManaged
		$a_01_6 = {43 00 6f 00 63 00 6b 00 6f 00 73 00 20 00 49 00 6e 00 63 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 65 00 64 00 } //1 Cockos Incorporated
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=25
 
}