
rule TrojanDropper_Win32_Fedripto_A{
	meta:
		description = "TrojanDropper:Win32/Fedripto.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 30 74 05 80 c1 ?? eb 03 80 c1 ?? 88 0c 30 8b 4c 24 10 40 3b c1 72 d8 } //1
		$a_01_1 = {46 64 72 31 33 38 69 70 32 00 } //1 摆ㅲ㠳灩2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}