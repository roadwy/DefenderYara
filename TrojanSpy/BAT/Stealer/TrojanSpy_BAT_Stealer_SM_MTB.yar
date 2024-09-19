
rule TrojanSpy_BAT_Stealer_SM_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 59 00 00 0a 13 09 12 09 fe 16 28 00 00 01 6f 5a 00 00 0a 28 41 00 00 0a 28 2d 00 00 0a 16 13 08 de 03 } //2
		$a_01_1 = {69 6d 61 67 65 63 6c 61 73 73 2e 65 78 65 } //2 imageclass.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}