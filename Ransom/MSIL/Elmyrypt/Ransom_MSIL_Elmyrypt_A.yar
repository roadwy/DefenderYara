
rule Ransom_MSIL_Elmyrypt_A{
	meta:
		description = "Ransom:MSIL/Elmyrypt.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 6c 6d 65 72 73 20 47 6c 75 65 20 4c 6f 63 6b 65 72 } //1 Elmers Glue Locker
		$a_01_1 = {66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 63 00 6f 00 76 00 65 00 72 00 65 00 64 00 20 00 69 00 6e 00 20 00 76 00 65 00 72 00 79 00 20 00 73 00 74 00 69 00 63 00 6b 00 79 00 20 00 45 00 6c 00 6d 00 65 00 72 00 27 00 73 00 20 00 47 00 6c 00 75 00 65 00 21 00 } //1 files have been covered in very sticky Elmer's Glue!
		$a_01_2 = {31 00 44 00 72 00 76 00 39 00 6a 00 41 00 4d 00 73 00 56 00 5a 00 50 00 65 00 75 00 72 00 31 00 38 00 7a 00 62 00 6d 00 74 00 4a 00 54 00 63 00 69 00 41 00 6d 00 61 00 6a 00 35 00 4c 00 39 00 62 00 6f 00 } //2 1Drv9jAMsVZPeur18zbmtJTciAmaj5L9bo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}