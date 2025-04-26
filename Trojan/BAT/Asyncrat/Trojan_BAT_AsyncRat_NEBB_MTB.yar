
rule Trojan_BAT_AsyncRat_NEBB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 08 28 31 00 00 0a 7e 0a 00 00 04 6f 32 00 00 0a 6f 33 00 00 0a 6f 34 00 00 0a 06 18 6f 35 00 00 0a 06 6f 36 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 37 00 00 0a 0b de 11 } //10
		$a_01_1 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //2 get_Computer
		$a_01_2 = {41 45 53 5f 44 65 63 72 79 70 74 6f 72 } //2 AES_Decryptor
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}