
rule Trojan_AndroidOS_KoSpy_B_MTB{
	meta:
		description = "Trojan:AndroidOS/KoSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {36 76 37 00 20 46 1f 01 38 06 33 00 71 00 9e 0d 00 00 0c 06 6e 10 9f 0d 06 00 0a 06 38 06 13 00 32 26 06 00 12 34 32 46 0e 00 28 22 1f 04 1f 01 } //1
		$a_01_1 = {54 02 31 05 54 22 3c 05 54 04 30 05 54 05 a5 05 6e 40 03 30 42 51 0c 02 5b 02 a9 05 39 02 10 00 71 00 de 2f 00 00 0c 01 62 02 aa 05 1a 04 7f 17 23 33 1c 0d 6e 40 dc 2f 21 34 28 1d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}