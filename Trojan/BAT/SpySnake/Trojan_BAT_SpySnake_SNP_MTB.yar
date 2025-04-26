
rule Trojan_BAT_SpySnake_SNP_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.SNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 50 8e 69 17 58 8d 09 00 00 02 0a 16 0b 2b 10 00 06 07 7e 04 00 00 04 07 9a a2 00 07 17 58 0b 07 7e 04 00 00 04 8e 69 fe 04 0c 08 2d e2 02 06 51 2a } //2
		$a_01_1 = {56 75 57 6d 2e 65 78 65 } //1 VuWm.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}