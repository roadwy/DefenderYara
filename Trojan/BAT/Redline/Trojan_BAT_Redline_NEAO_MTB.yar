
rule Trojan_BAT_Redline_NEAO_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 2b 00 00 0a 28 2c 00 00 0a 72 2d 00 00 70 28 2d 00 00 0a 28 22 00 00 06 28 2e 00 00 0a 15 16 28 2f 00 00 0a 80 0a 00 00 04 7e 0a 00 00 04 17 9a 28 2e 00 00 0a 28 2d 00 00 0a 28 22 00 00 06 28 2e 00 00 0a 28 2d 00 00 0a 80 0b 00 00 04 2a } //10
		$a_01_1 = {43 70 79 6f 4d 61 6e 43 41 79 54 43 } //2 CpyoManCAyTC
		$a_01_2 = {4a 41 76 41 79 77 6f 6e 6f 62 52 66 44 41 70 79 73 77 } //2 JAvAywonobRfDApysw
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}