
rule TrojanSpy_BAT_Stealer_SO_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 3c 11 0e 11 3c 11 1f 59 61 13 0e 11 1f 11 0e 17 63 58 13 1f } //2
		$a_01_1 = {69 6d 61 67 65 63 6c 61 73 73 2e 65 78 65 } //2 imageclass.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}