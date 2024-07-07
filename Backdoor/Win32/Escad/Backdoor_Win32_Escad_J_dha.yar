
rule Backdoor_Win32_Escad_J_dha{
	meta:
		description = "Backdoor:Win32/Escad.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 08 33 c7 83 c1 04 c1 e0 08 33 c3 c1 e0 08 8b d0 33 d5 8b c2 89 91 } //10
		$a_00_1 = {73 6b 69 6e 70 66 75 2e 64 61 74 } //1 skinpfu.dat
		$a_00_2 = {73 6b 6d 73 76 78 64 2e 64 61 74 } //1 skmsvxd.dat
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}
rule Backdoor_Win32_Escad_J_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2e 00 78 00 6c 00 73 00 90 02 06 2e 00 77 00 72 00 69 00 90 02 06 2e 00 77 00 70 00 78 00 90 02 06 2e 00 77 00 70 00 64 00 90 02 06 2e 00 64 00 6f 00 63 00 6d 00 90 02 06 2e 00 64 00 6f 00 63 00 78 00 90 02 06 2e 00 64 00 6f 00 63 00 90 02 06 2e 00 63 00 61 00 62 00 90 02 20 25 00 63 00 3a 00 5c 00 90 02 10 5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 25 00 64 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Backdoor_Win32_Escad_J_dha_3{
	meta:
		description = "Backdoor:Win32/Escad.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 0d 0a 64 65 6c 20 2f 61 20 22 25 73 22 90 02 50 4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 90 00 } //1
		$a_03_1 = {8b c1 33 d2 be 90 01 04 f7 f6 8a 82 90 01 04 8a 91 90 01 04 32 d0 88 91 90 01 04 41 81 f9 90 01 04 72 d8 90 00 } //1
		$a_00_2 = {c6 44 24 16 2e f7 f9 c6 44 24 17 64 c6 44 24 18 6c c6 44 24 19 6c } //1
		$a_02_3 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 90 02 05 68 74 74 70 3a 2f 2f 90 02 60 2e 65 78 65 90 02 20 53 74 61 72 74 49 6e 73 74 61 6c 6c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}
rule Backdoor_Win32_Escad_J_dha_4{
	meta:
		description = "Backdoor:Win32/Escad.J!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 75 73 65 72 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 25 73 } //1 cmd.exe /c net user Administrator %s
		$a_01_1 = {48 61 48 61 48 61 5f 25 64 25 64 25 64 25 64 } //1 HaHaHa_%d%d%d%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Backdoor_Win32_Escad_J_dha_5{
	meta:
		description = "Backdoor:Win32/Escad.J!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 75 73 65 72 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 25 73 } //1 cmd.exe /c net user Administrator %s
		$a_01_1 = {48 61 48 61 48 61 5f 25 64 25 64 25 64 25 64 } //1 HaHaHa_%d%d%d%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}