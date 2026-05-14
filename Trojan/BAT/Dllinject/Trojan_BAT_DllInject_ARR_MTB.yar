
rule Trojan_BAT_DllInject_ARR_MTB{
	meta:
		description = "Trojan:BAT/DllInject.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 17 58 0b 07 02 8e 32 e8 2b 03 17 13 04 } //6
		$a_01_1 = {12 07 1e 58 4a 16 33 03 16 2b 01 17 d2 2d 02 de 0e } //4
		$a_81_2 = {52 33 6e 7a 53 6b 69 6e 5f 49 6e 6a 65 63 74 6f 72 2e 65 78 65 } //10 R3nzSkin_Injector.exe
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*4+(#a_81_2  & 1)*10) >=20
 
}