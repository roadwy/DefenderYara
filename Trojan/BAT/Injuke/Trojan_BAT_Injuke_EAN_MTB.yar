
rule Trojan_BAT_Injuke_EAN_MTB{
	meta:
		description = "Trojan:BAT/Injuke.EAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {1a 2d 24 26 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 1c 2d 13 26 07 16 07 8e 69 1d 2d 0d 26 26 26 07 0c de 10 0a 2b da 0b 2b eb 28 ?? 00 00 0a 2b ef 26 de be } //3
		$a_01_1 = {70 00 61 00 77 00 65 00 65 00 72 00 2e 00 72 00 75 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 42 00 77 00 75 00 66 00 78 00 79 00 6a 00 74 00 2e 00 62 00 6d 00 70 00 } //2 paweer.ru/panel/uploads/Bwufxyjt.bmp
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}