
rule Trojan_BAT_FormBook_BRAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1b 00 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d dd } //4
		$a_01_1 = {43 00 36 00 43 00 36 00 34 00 36 00 45 00 32 00 35 00 36 00 35 00 36 00 32 00 37 00 46 00 36 00 33 00 36 00 33 00 37 00 44 00 36 00 } //2 C6C646E2565627F63637D6
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}