
rule Trojan_Win32_Raccrypt_GL_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c3 81 05 ?? ?? ?? ?? d6 38 00 00 c3 81 05 ?? ?? ?? ?? 00 00 00 00 c3 ff 25 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GL_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {32 2e 64 6c c7 05 ?? ?? ?? ?? 6b 65 72 6e 66 c7 05 ?? ?? ?? ?? 65 6c c6 05 ?? ?? ?? ?? 33 66 c7 05 ?? ?? ?? ?? 6c 00 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GL_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b [0-14] c1 ?? 05 03 [0-1e] c1 ?? 04 03 [0-0f] 33 } //1
		$a_00_1 = {33 44 24 04 c2 04 00 81 00 f6 34 ef c6 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GL_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b4 02 d7 cb [0-06] c7 05 ?? ?? ?? ?? ff ff ff ff [0-0a] 90 18 55 8b ec 81 ec 00 01 00 00 c7 [0-06] 57 78 d1 51 c7 [0-06] 0b 4c 1b 7e c7 [0-06] dd 0b fa 64 c7 [0-06] cf 72 b2 3d c7 [0-06] e9 0e 74 64 c7 [0-06] a9 53 5d 16 c7 [0-06] 05 c8 4e 43 c7 [0-06] 82 2d 68 68 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Raccrypt_GL_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {4a d0 8a 2c c7 84 24 ?? ?? ?? ?? 15 6e 75 0e c7 84 24 ?? ?? ?? ?? 8e 52 57 39 c7 84 24 ?? ?? ?? ?? 5b 4a 15 44 c7 84 24 ?? ?? ?? ?? 0c ba 12 32 c7 84 24 ?? ?? ?? ?? 87 7d 73 71 } //1
		$a_02_1 = {65 aa 60 60 c7 84 24 ?? ?? ?? ?? 50 c8 81 35 c7 84 24 ?? ?? ?? ?? 1e e5 bc 4b c7 84 24 ?? ?? ?? ?? df 02 30 6d c7 84 24 ?? ?? ?? ?? 86 d5 5b 70 c7 84 24 ?? ?? ?? ?? 0b ef cb 64 } //1
		$a_02_2 = {86 22 d0 1b c7 84 24 ?? ?? ?? ?? bc ac 35 50 c7 84 24 ?? ?? ?? ?? b5 8b ad 60 c7 84 24 ?? ?? ?? ?? e2 84 9c 35 c7 84 24 ?? ?? ?? ?? 49 b7 1d 24 c7 84 24 ?? ?? ?? ?? 33 aa 61 23 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GL_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 04 03 [0-1e] c1 ?? 05 03 [0-0f] 90 17 02 01 01 31 33 } //1
		$a_02_1 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 05 03 [0-1e] c1 ?? 04 03 [0-0f] 90 17 02 01 01 31 33 } //1
		$a_02_2 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 04 03 [0-1e] c1 ?? 05 03 90 0a 0f 00 90 17 02 01 01 31 33 } //1
		$a_02_3 = {b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 90 0a 32 00 c1 ?? 05 03 [0-1e] c1 ?? 04 03 90 0a 0f 00 90 17 02 01 01 31 33 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}