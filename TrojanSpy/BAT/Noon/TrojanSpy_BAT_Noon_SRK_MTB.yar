
rule TrojanSpy_BAT_Noon_SRK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 11 3f 11 40 91 6f 22 01 00 0a 00 11 14 1d 17 9c 11 0c 11 3f 11 40 91 58 13 0c 00 11 40 17 58 13 40 11 40 11 32 fe 04 13 41 11 41 2d d1 } //2
		$a_01_1 = {51 4c 4e 53 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 QLNS.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}