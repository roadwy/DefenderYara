
rule TrojanSpy_BAT_Kabolog_A{
	meta:
		description = "TrojanSpy:BAT/Kabolog.A,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {08 06 16 20 b3 ea 65 15 20 b3 da 65 15 59 6f a4 00 00 0a 13 08 } //5
		$a_01_1 = {40 00 6b 00 6f 00 6c 00 61 00 2d 00 62 00 6f 00 6b 00 61 00 } //5 @kola-boka
		$a_01_2 = {5b 00 47 00 75 00 69 00 6c 00 6c 00 65 00 6d 00 65 00 74 00 73 00 5d 00 } //1 [Guillemets]
		$a_01_3 = {73 65 74 5f 48 4b 42 } //1 set_HKB
		$a_01_4 = {63 61 70 73 73 68 69 66 74 } //1 capsshift
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}