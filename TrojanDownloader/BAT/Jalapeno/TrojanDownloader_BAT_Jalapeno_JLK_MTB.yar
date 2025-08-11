
rule TrojanDownloader_BAT_Jalapeno_JLK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Jalapeno.JLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 1f 00 00 0a 25 6f 20 00 00 0a 72 61 00 00 70 72 77 00 00 70 6f 21 00 00 0a 25 72 6e 01 00 70 6f 22 00 00 0a 0a 6f 23 00 00 0a dd 03 00 00 00 26 de cc 02 06 28 01 00 00 2b 28 02 00 00 2b 28 26 00 00 0a 28 27 00 00 0a } //2
		$a_01_1 = {02 7b 05 00 00 04 72 12 02 00 70 28 1e 00 00 0a 26 02 28 2a 00 00 0a 75 18 00 00 01 72 20 02 00 70 6f 2b 00 00 0a 72 6c 02 00 70 1f 18 6f 2c 00 00 0a 0a 06 14 28 2d 00 00 0a 39 05 00 00 00 dd 1a 00 00 00 06 14 14 6f 2e 00 00 0a 26 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}