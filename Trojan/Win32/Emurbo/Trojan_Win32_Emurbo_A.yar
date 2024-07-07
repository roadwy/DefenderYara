
rule Trojan_Win32_Emurbo_A{
	meta:
		description = "Trojan:Win32/Emurbo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {76 27 88 04 24 b3 01 8b c6 e8 90 01 03 ff 8b fb 81 e7 ff 00 00 00 8b 16 8a 54 3a ff 80 f2 10 88 54 38 ff 43 fe 0c 24 75 de 90 00 } //3
		$a_01_1 = {68 74 74 70 3a 2f 2f 66 6c 79 63 6f 64 65 63 73 2e 63 6f 6d 2f 6f 70 61 2f 75 70 64 61 74 65 2e 70 68 70 3f 61 3d 00 } //1
		$a_01_2 = {55 70 64 50 6f 69 6e 74 00 } //1
		$a_01_3 = {3f 6b 65 79 3d 00 00 00 ff ff ff ff 06 00 00 00 3f 66 69 6e 64 3d } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}