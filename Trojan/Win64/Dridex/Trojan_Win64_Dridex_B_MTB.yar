
rule Trojan_Win64_Dridex_B_MTB{
	meta:
		description = "Trojan:Win64/Dridex.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {49 81 f1 b9 74 b6 60 4c 8b 15 3d 3e 00 00 ba 7e d6 44 00 89 d6 48 89 4c 24 60 48 89 f1 4c 89 ca 48 89 44 24 58 41 ff d2 48 8d 8c 24 c0 00 00 00 48 8b 54 24 68 48 81 fa 95 e2 c4 62 89 44 24 54 48 89 4c 24 48 } //10
		$a_80_1 = {4b 69 6c 6c 54 69 6d 65 72 } //KillTimer  3
		$a_80_2 = {45 6e 64 44 65 66 65 72 57 69 6e 64 6f 77 50 6f 73 } //EndDeferWindowPos  3
		$a_80_3 = {52 70 63 49 6d 70 65 72 73 6f 6e 61 74 65 43 6c 69 65 6e 74 } //RpcImpersonateClient  3
		$a_80_4 = {4f 65 6d 54 6f 43 68 61 72 42 75 66 66 57 } //OemToCharBuffW  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}