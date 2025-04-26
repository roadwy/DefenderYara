
rule TrojanDropper_Win32_Vundo_K{
	meta:
		description = "TrojanDropper:Win32/Vundo.K,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 62 56 d7 17 8d aa a7 b5 5d cb 32 c8 82 1a fa de f0 2c 36 76 dd 54 05 } //1
		$a_01_1 = {89 55 e0 8b c2 c1 e8 18 c1 e2 08 0b c2 89 45 e0 2b c1 89 45 e0 33 c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}