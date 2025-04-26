
rule Trojan_BAT_FormBook_A_MTB{
	meta:
		description = "Trojan:BAT/FormBook.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 73 20 00 00 0a 0a 73 1e 00 00 06 0b 1b 8d 92 00 00 01 0c 06 08 16 1b 6f 21 00 00 0a 26 07 08 6f 24 00 00 06 16 6a 0d 16 13 06 2b 1d 06 6f 22 00 00 0a } //2
		$a_01_1 = {63 34 31 66 34 32 62 33 2d 35 38 37 32 2d 34 31 31 38 2d 61 36 34 65 2d 39 30 65 37 32 33 36 33 37 66 66 36 } //1 c41f42b3-5872-4118-a64e-90e723637ff6
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}