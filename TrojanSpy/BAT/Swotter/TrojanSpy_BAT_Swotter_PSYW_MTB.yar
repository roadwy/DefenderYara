
rule TrojanSpy_BAT_Swotter_PSYW_MTB{
	meta:
		description = "TrojanSpy:BAT/Swotter.PSYW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 25 6f 15 90 02 03 0a 06 6f 90 01 03 0a 6f 90 01 03 0a 06 6f 90 01 03 0a 06 6f 90 01 03 0a 0b dd 03 00 00 00 26 de b9 90 00 } //1
		$a_03_1 = {0a 0c 06 08 6f 90 01 03 0a 06 18 6f 90 01 03 0a 02 0d 06 6f 90 01 03 0a 09 16 09 8e 69 6f 90 01 03 0a 13 04 dd 1a 90 00 } //1
		$a_03_2 = {0a 16 fe 02 39 90 01 03 00 06 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 0b 28 90 01 03 0a 6f 90 01 03 0a 6f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}