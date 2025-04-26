
rule Trojan_BAT_FileCoder_DF_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 2e 00 00 0a 11 07 6f 2f 00 00 0a 13 08 73 13 00 00 06 13 09 } //4
		$a_00_1 = {56 00 6f 00 74 00 72 00 65 00 20 00 43 00 6c 00 65 00 20 00 70 00 6f 00 75 00 72 00 20 00 70 00 61 00 79 00 6d 00 65 00 6e 00 74 00 } //3 Votre Cle pour payment
		$a_00_2 = {43 3a 5c 55 73 65 72 73 5c 59 61 6e 6e 69 73 5c 44 65 73 6b 74 6f 70 5c 6d 61 6a 6f 72 64 6f 6d 5c 63 6c 69 65 6e 74 5c 6d 61 6a 6f 72 5c 6d 61 6a 6f 72 64 6f 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 6d 61 6a 6f 72 2e 70 64 62 } //3 C:\Users\Yannis\Desktop\majordom\client\major\majordom\obj\Debug\major.pdb
	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3) >=10
 
}