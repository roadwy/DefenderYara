
rule TrojanSpy_Win32_Bancos_LH{
	meta:
		description = "TrojanSpy:Win32/Bancos.LH,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 62 72 61 64 65 73 63 6f 6e 65 74 65 6d 70 72 65 73 61 2e 63 6f 6d 2e 62 72 20 2d 20 20 42 72 61 64 65 73 63 6f 20 2d 20 43 6f 6c 6f 63 61 6e 64 6f 20 76 6f 63 ea 20 73 65 6d 70 72 65 20 61 20 66 72 65 6e 74 65 20 2d 20 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1
		$a_01_1 = {5c 00 69 00 6e 00 69 00 64 00 69 00 72 00 78 00 2e 00 69 00 6e 00 69 00 } //1 \inidirx.ini
		$a_01_2 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 31 00 2e 00 30 00 3a 00 20 00 21 00 20 00 72 00 30 00 78 00 20 00 21 00 20 00 61 00 20 00 21 00 20 00 6c 00 6f 00 74 00 20 00 21 00 20 00 3d 00 44 00 20 00 21 00 20 00 2d 00 20 00 5b 00 5d 00 78 00 5e 00 78 00 5b 00 5d 00 } //1 Version 1.0: ! r0x ! a ! lot ! =D ! - []x^x[]
		$a_01_3 = {4a 00 75 00 6d 00 65 00 6e 00 74 00 69 00 6e 00 68 00 61 00 20 00 63 00 68 00 65 00 67 00 61 00 6e 00 64 00 6f 00 } //1 Jumentinha chegando
		$a_01_4 = {28 00 20 00 4d 00 61 00 52 00 61 00 6e 00 48 00 61 00 4f 00 20 00 2d 00 20 00 37 00 2e 00 30 00 } //1 ( MaRanHaO - 7.0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}