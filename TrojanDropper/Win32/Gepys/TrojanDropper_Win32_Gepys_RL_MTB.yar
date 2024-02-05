
rule TrojanDropper_Win32_Gepys_RL_MTB{
	meta:
		description = "TrojanDropper:Win32/Gepys.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {d3 e0 69 c0 0f e9 00 00 8b 0d 90 01 04 31 d2 80 c9 01 a3 90 01 04 89 d8 f7 f1 03 05 90 01 04 69 c0 29 cd 02 00 01 d8 31 d2 05 af 48 04 00 8d 4b 01 a3 90 01 04 a1 90 01 04 f7 f1 69 c0 ef e0 04 00 88 d9 d3 e8 05 29 14 03 00 a3 90 01 04 a1 90 01 04 31 d2 09 d8 8b 0d 90 01 04 05 c3 43 01 00 80 c9 01 a3 90 01 04 89 d8 f7 f1 b9 4c ff 00 00 03 05 90 01 04 31 d2 f7 f1 89 15 90 00 } //02 00 
		$a_02_1 = {29 c1 31 d2 89 c8 b9 9e 00 01 00 f7 f1 a1 90 01 04 89 15 90 01 04 01 d8 31 d2 05 b5 92 02 00 8d 4b 01 a3 90 01 04 f7 f1 b9 b3 fe 00 00 31 d2 f7 f1 b9 89 0b 01 00 a1 90 01 04 89 15 90 01 04 09 d8 31 d2 f7 f1 b9 70 03 01 00 8d 43 ff 89 15 90 01 04 23 05 90 01 04 31 d2 f7 f1 8b 0d 90 01 04 89 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}