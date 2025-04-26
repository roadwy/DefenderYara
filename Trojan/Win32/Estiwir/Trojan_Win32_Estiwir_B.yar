
rule Trojan_Win32_Estiwir_B{
	meta:
		description = "Trojan:Win32/Estiwir.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 06 80 f1 ?? 88 08 40 4f 75 f4 } //1
		$a_01_1 = {45 00 73 00 74 00 52 00 74 00 77 00 49 00 46 00 44 00 72 00 76 00 } //1 EstRtwIFDrv
		$a_01_2 = {00 25 64 25 64 25 64 25 64 25 64 2e 65 78 65 00 } //1
		$a_03_3 = {8a 14 01 80 f2 ?? 88 10 40 4e 75 f4 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}