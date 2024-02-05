
rule TrojanDropper_Win32_Dapato_SV_MTB{
	meta:
		description = "TrojanDropper:Win32/Dapato.SV!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {69 62 f6 e4 73 07 fa 7b 2e 13 } //02 00 
		$a_01_1 = {6d 77 fb fa 7f 09 cf 7b 36 7f 10 66 f5 44 e3 20 f6 21 30 18 ec } //02 00 
		$a_01_2 = {56 4c c9 dc 36 41 ec 6e 2a 60 5a 28 aa 51 f9 17 b6 23 26 18 98 33 72 e7 e2 ec e9 19 a5 64 24 7f 60 3a 2d ea 93 e6 09 ae f0 61 14 0f 4d 40 4b 37 } //00 00 
	condition:
		any of ($a_*)
 
}