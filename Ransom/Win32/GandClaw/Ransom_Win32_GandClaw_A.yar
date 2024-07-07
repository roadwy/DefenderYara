
rule Ransom_Win32_GandClaw_A{
	meta:
		description = "Ransom:Win32/GandClaw.A,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 05 00 00 "
		
	strings :
		$a_00_0 = {c7 45 e0 99 a9 aa aa 50 57 c7 45 e4 ed fe ad de c7 45 f0 00 00 00 00 } //20
		$a_00_1 = {81 7d e0 99 a9 aa aa 75 a2 } //20
		$a_03_2 = {0f 57 c0 c7 45 e8 00 00 00 00 68 90 01 04 6a 00 f3 0f 7f 45 a8 6a 00 8b f1 c7 45 a8 44 00 00 00 f3 0f 7f 45 b8 f3 0f 7f 45 c8 f3 0f 7f 45 d8 f3 0f 7f 45 f0 ff 15 90 01 04 8b f8 8d 45 f0 50 8d 45 a8 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 56 ff 15 90 00 } //20
		$a_80_3 = {4c 50 45 20 44 4c 4c 3a 20 54 72 79 69 6e 67 20 74 6f 20 4f 70 65 6e 20 50 69 70 65 20 2d 20 25 77 73 } //LPE DLL: Trying to Open Pipe - %ws  10
		$a_80_4 = {4c 50 45 20 44 4c 4c 3a 20 54 61 72 67 65 74 20 70 61 74 68 3a 20 25 77 73 } //LPE DLL: Target path: %ws  10
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*20+(#a_03_2  & 1)*20+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10) >=60
 
}