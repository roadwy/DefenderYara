
rule Trojan_BAT_Rozena_NE_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 04 09 11 04 09 6f 20 00 00 0a 1e 5b 6f 21 00 00 0a 6f 22 00 00 0a 00 09 11 04 09 6f 23 00 00 0a 1e 5b 6f 21 00 00 0a } //3
		$a_03_1 = {0c 02 07 28 ?? 00 00 2b 28 ?? 00 00 06 00 02 28 ?? 00 00 06 0d 09 2c 11 } //2
		$a_01_2 = {41 45 53 5f 65 6e 63 72 79 70 74 2e 65 78 65 } //1 AES_encrypt.exe
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}