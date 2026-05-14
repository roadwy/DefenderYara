
rule Trojan_Win32_Remcos_ARK_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 ff d6 bb a4 10 41 00 68 94 10 41 00 53 a3 34 59 41 00 ff d7 50 ff d6 68 80 10 41 00 53 a3 94 5b 41 00 ff d7 50 ff d6 68 70 10 41 00 68 68 10 41 00 a3 98 5b 41 00 ff d7 50 ff d6 68 54 10 41 00 53 } //2
		$a_03_1 = {56 57 68 0c 11 41 00 68 00 11 41 00 ff d3 8b 35 44 01 41 00 50 ff d6 8b 3d ?? 01 41 00 a3 2c 59 41 00 85 c0 75 14 68 0c 11 41 00 68 f0 10 41 00 ff d7 50 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}