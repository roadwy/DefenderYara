
rule TrojanDropper_Win32_Tracur_gen_I{
	meta:
		description = "TrojanDropper:Win32/Tracur.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 45 d4 29 e0 75 07 8b 4d 00 85 c9 74 90 04 01 02 25 23 55 89 e5 80 7d 0c 01 75 90 04 01 02 24 22 ba ?? ?? ?? ?? 56 52 b9 ?? ?? ?? ?? (31 d1|) be ?? 90 04 01 02 20 10 00 00 03 75 08 81 f1 ?? ?? ?? ?? d3 ca 30 36 ac e2 f9 } //1
		$a_03_1 = {8d 45 d4 29 ?? 75 90 04 01 02 08 07 8b 4d 00 90 05 01 01 90 85 c9 74 25 55 89 e5 80 7d 0c 01 75 ?? ba ?? ?? ?? ?? 56 52 b9 ?? ?? ?? ?? 31 d1 be ?? ?? 00 00 81 f1 ?? ?? ?? ?? 03 75 08 [0-05] d3 ca [0-05] 30 36 ac [0-05] e2 } //1
		$a_03_2 = {8d 45 d4 29 e0 75 ?? 8b 4d 00 90 05 01 01 90 85 c9 74 25 55 89 e5 80 7d 0c 01 75 27 ba ?? ?? ?? ?? 56 52 b9 ?? ?? ?? ?? 31 d1 be ?? 10 00 00 81 f1 ?? ?? ?? ?? 03 75 08 d3 ca 83 fa 00 30 36 ac e2 f6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}