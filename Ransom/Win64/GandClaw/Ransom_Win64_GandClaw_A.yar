
rule Ransom_Win64_GandClaw_A{
	meta:
		description = "Ransom:Win64/GandClaw.A,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 bd 99 a9 aa aa ed 44 8b c3 48 8b cf 89 44 24 ?? 48 89 6c 24 ?? 44 89 b4 24 ?? 00 00 00 4c 89 74 24 ?? ff 15 } //20
		$a_03_1 = {33 d2 33 c9 c7 44 24 ?? 68 00 00 00 ff 15 ?? ?? ?? ?? 45 33 c9 48 8b d8 48 8d 44 24 ?? 45 33 c0 48 89 44 24 ?? 48 8d 44 24 ?? 33 d2 48 89 44 24 ?? 48 89 74 24 ?? 48 89 74 24 ?? 48 8b cf 89 74 24 ?? 89 74 24 ?? ff 15 8b 0c 00 00 85 c0 74 ?? 48 8b 4c 24 ?? ba 10 27 00 00 ff 15 } //20
		$a_00_2 = {33 c9 8d 50 02 41 b8 00 30 00 00 44 8d 49 04 ff 15 } //20
		$a_80_3 = {4c 50 45 20 44 4c 4c 3a 20 54 72 79 69 6e 67 20 74 6f 20 4f 70 65 6e 20 50 69 70 65 20 2d 20 25 77 73 } //LPE DLL: Trying to Open Pipe - %ws  10
		$a_80_4 = {4c 50 45 20 44 4c 4c 3a 20 54 61 72 67 65 74 20 70 61 74 68 3a 20 25 77 73 } //LPE DLL: Target path: %ws  10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*20+(#a_00_2  & 1)*20+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10) >=60
 
}