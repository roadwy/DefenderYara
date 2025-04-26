
rule TrojanSpy_BAT_Noon_SEK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 6b 77 61 73 2e 46 6f 72 6d 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 skwas.Forms.Properties.Resources
		$a_81_1 = {64 66 34 30 36 65 61 62 2d 38 62 65 30 2d 34 37 36 34 2d 62 34 66 38 2d 32 38 35 31 32 66 63 31 39 34 38 39 } //2 df406eab-8be0-4764-b4f8-28512fc19489
		$a_81_2 = {32 30 30 37 2d 32 30 30 39 20 73 6b 77 61 73 } //2 2007-2009 skwas
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}