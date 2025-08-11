
rule TrojanSpy_BAT_Noon_SSK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 03 7b ca 00 00 04 11 11 91 11 11 1e 5a 1f 1f 5f 62 58 0a 00 11 11 17 58 13 11 11 11 03 7b ca 00 00 04 8e 69 1a 28 19 01 00 0a fe 04 13 12 11 12 2d cc } //2
		$a_01_1 = {54 65 74 72 69 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 Tetris.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}