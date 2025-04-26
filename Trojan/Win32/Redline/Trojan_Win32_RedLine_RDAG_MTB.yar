
rule Trojan_Win32_RedLine_RDAG_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 Explorer.exe
		$a_01_1 = {4e 33 ce 33 ce 46 f7 d9 c1 c1 09 33 cc f7 de 21 05 b2 a7 40 00 46 b9 57 a4 04 00 03 cb 03 0d bf af 40 00 87 f7 0b 1d 13 ae 40 00 31 35 f6 a6 40 00 4b 31 0d df aa 40 00 33 0d 63 af 40 00 47 31 3d 9a a9 40 00 f7 d7 21 15 dc a8 40 00 33 15 34 ae 40 00 c1 c9 0d c1 c1 0d f7 d7 09 0d 9d a8 40 00 4f 89 05 0a ab 40 00 43 31 3d 13 aa 40 00 87 f7 2b cb f3 a4 f7 d6 33 f7 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}