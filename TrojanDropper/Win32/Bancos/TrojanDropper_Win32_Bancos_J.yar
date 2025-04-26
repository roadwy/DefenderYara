
rule TrojanDropper_Win32_Bancos_J{
	meta:
		description = "TrojanDropper:Win32/Bancos.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0c f8 00 00 73 65 78 6f 00 } //1
		$a_10_1 = {00 43 00 3a 00 5c 00 49 00 6e 00 63 00 6c 00 75 00 64 00 65 00 5c 00 00 } //1
		$a_03_2 = {a3 48 4b be 98 6c 4a a9 99 4c 53 0a 86 d6 48 7d 66 6f 6f 6c 44 37 39 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5e 6f fe 78 af ad 00 00 e6 fb 25 78 c8 e2 13 f9 7d 1d ed dd 71 00 b0 55 2d ac 9a d5 28 15 d4 f0 cf 25 e4 cf 11 8e 56 c2 ce 3f 70 ef b9 68 0c f8 00 00 06 50 c5 71 70 8e 4a 74 2e 3a df a5 ef 68 29 bc d2 9b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_10_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}