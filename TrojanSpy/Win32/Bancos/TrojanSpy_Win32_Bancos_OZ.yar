
rule TrojanSpy_Win32_Bancos_OZ{
	meta:
		description = "TrojanSpy:Win32/Bancos.OZ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 62 72 69 6e 66 6f 32 30 30 39 40 67 6d 61 69 6c 2e 63 6f 6d } //1 =brinfo2009@gmail.com
		$a_01_1 = {2e 74 78 74 00 00 42 72 61 64 65 73 63 6f 55 70 64 61 74 65 00 } //1
		$a_01_2 = {2f 65 6e 76 69 61 64 6f 72 2e 70 68 70 } //1 /enviador.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}