
rule TrojanSpy_BAT_Noon_SMK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 19 28 4e 00 00 06 0a 04 07 08 91 6f a1 00 00 0a 00 00 08 17 58 0c 08 03 fe 04 0d 09 2d e0 } //2
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 4f 43 52 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 WindowsFormsOCR.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}