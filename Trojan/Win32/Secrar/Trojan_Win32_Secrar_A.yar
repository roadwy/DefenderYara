
rule Trojan_Win32_Secrar_A{
	meta:
		description = "Trojan:Win32/Secrar.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 83 7d 08 05 75 90 01 01 83 7d fc 00 75 90 01 01 c7 45 f4 00 00 00 00 8b 4d 0c 89 4d f8 8b 55 f8 89 55 f4 8b 45 f4 8b 4d f4 03 08 89 4d f8 8b 55 f8 0f b7 42 38 50 90 00 } //1
		$a_01_1 = {8b 55 f4 8b 02 8b 4d f8 03 01 8b 55 f4 89 02 8b 45 f4 89 45 f8 8b 4d f4 83 39 00 75 } //1
		$a_00_2 = {73 00 76 00 63 00 68 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 svchst.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}