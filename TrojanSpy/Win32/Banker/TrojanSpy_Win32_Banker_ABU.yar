
rule TrojanSpy_Win32_Banker_ABU{
	meta:
		description = "TrojanSpy:Win32/Banker.ABU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 a1 30 2f 47 00 8b 08 ff 51 38 8d 45 f0 50 8b 0d 30 2f 47 00 ba 90 01 04 8b 83 00 03 00 00 e8 90 00 } //1
		$a_03_1 = {73 75 62 6a 65 63 74 3d 90 01 0c 6d 65 73 73 61 67 65 3d 90 01 18 68 74 74 70 3a 2f 2f 90 00 } //1
		$a_01_2 = {54 65 63 6c 61 64 6f 20 76 69 72 74 75 61 6c 20 64 65 73 61 62 69 6c 69 74 61 64 6f 2c 20 70 6f 72 20 66 61 76 6f 72 20 75 74 69 6c 69 7a 65 20 73 65 75 20 74 65 63 6c 61 64 6f } //1 Teclado virtual desabilitado, por favor utilize seu teclado
		$a_01_3 = {41 74 75 61 6c 69 7a 61 6e 64 6f 20 2d 20 45 74 61 70 61 20 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}