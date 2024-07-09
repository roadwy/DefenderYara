
rule Trojan_Win32_Estiwir_A{
	meta:
		description = "Trojan:Win32/Estiwir.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 ?? 88 10 40 4e 75 f4 } //1
		$a_01_1 = {03 c6 ff d0 33 c0 eb 17 } //1
		$a_03_2 = {8a 54 38 05 2a d1 88 94 3d ?? ?? ff ff 47 3b 38 72 ee } //1
		$a_01_3 = {25 64 25 64 25 64 25 64 25 64 2e 65 78 65 } //1 %d%d%d%d%d.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}