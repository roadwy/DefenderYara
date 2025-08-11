
rule Trojan_Win32_Tedy_LM_MTB{
	meta:
		description = "Trojan:Win32/Tedy.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 ef 83 ec 08 c7 45 fc 00 00 00 00 03 d7 c1 fa 10 8b c2 c1 e8 1f 03 c2 66 0f 6e c0 f3 0f e6 c0 f2 0f 11 85 78 ff ff ff dd 85 78 ff ff ff dd 1c 24 e8 ?? ?? ?? ?? 83 c4 08 dd 9d 78 ff ff ff f2 0f 10 85 78 ff ff ff e8 ?? ?? ?? ?? 8b f0 8b d7 69 ce 80 51 01 00 b8 c5 b3 a2 91 83 ec 08 89 b5 6c ff ff ff 2b d1 b9 18 00 00 00 f7 e2 c1 ea 0b 8b c2 } //20
		$a_03_1 = {0f 10 08 0f 28 c1 66 0f 73 d8 04 66 0f 7e c0 0f 28 c1 66 0f 73 d8 0c 66 0f 7e c1 2b c1 66 0f 7e c9 03 c6 66 0f 73 d9 08 8b b5 ec fe ff ff 99 2b c2 d1 f8 50 66 0f 7e c8 2b c8 8d 81 6a ff ff ff 03 c7 50 ff 36 e8 ?? ?? ?? ?? 83 c4 14 80 be d4 00 00 00 00 74 ?? 6a 01 ff 36 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}