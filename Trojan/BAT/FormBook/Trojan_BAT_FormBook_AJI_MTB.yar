
rule Trojan_BAT_FormBook_AJI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 2b 2d 06 6f 12 00 00 0a 74 0f 00 00 01 0b 07 6f 13 00 00 0a 6f 14 00 00 0a 02 6f 14 00 00 0a 6f 15 00 00 0a 2c 09 07 6f 16 00 00 0a 0c de 22 06 6f 17 00 00 0a 2d cb } //2
		$a_01_1 = {42 6c 61 63 6b 4d 61 69 6c 5f 50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 } //1 BlackMail_ProcessedByFody
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}