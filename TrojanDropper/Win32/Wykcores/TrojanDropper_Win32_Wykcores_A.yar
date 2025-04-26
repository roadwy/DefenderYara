
rule TrojanDropper_Win32_Wykcores_A{
	meta:
		description = "TrojanDropper:Win32/Wykcores.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 dc 8b 4d e0 8a 14 0a 8a 45 e0 2a d0 80 f2 17 02 d0 8b 45 dc 8b 4d e0 88 14 08 ff 45 e0 81 7d e0 00 04 00 00 75 d8 } //1
		$a_01_1 = {80 38 2a 74 22 46 40 4a 75 f6 eb 1b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}