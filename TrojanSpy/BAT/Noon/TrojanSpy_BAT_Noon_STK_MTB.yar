
rule TrojanSpy_BAT_Noon_STK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.STK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 7b 3a 01 00 04 07 11 05 91 6f b9 03 00 0a 00 00 11 05 17 58 13 05 11 05 06 2f 09 11 05 07 8e 69 fe 04 2b 01 16 13 06 11 06 2d d3 } //2
		$a_01_1 = {41 6e 61 6c 79 7a 65 47 72 61 70 68 69 63 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 AnalyzeGraphics.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}