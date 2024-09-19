
rule Trojan_Win32_AgentTesla_A_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {64 ff 30 64 89 20 ff 05 ?? ?? ?? 00 75 ?? 83 3d ?? ?? ?? 00 00 74 0a a1 ?? ?? ?? 00 e8 } //1
		$a_02_1 = {8b c7 8b de 8b d3 90 05 10 01 90 e8 ?? ?? ?? ?? 90 05 10 01 90 46 90 05 10 01 90 81 fe ?? ?? 00 00 75 } //1
		$a_02_2 = {8b c8 03 ca 8b c2 b2 ?? 32 90 90 ?? ?? ?? 00 88 11 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_Win32_AgentTesla_A_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 6c 2e 4f 0e 53 43 29 7b bc 63 67 b2 6f 63 2f eb 17 06 8a 32 7f f1 13 5f d2 e1 47 39 d2 2b 3d 53 56 11 bf 10 ea 03 36 45 12 c7 4d 89 6c 25 ce } //10
		$a_01_1 = {2e 76 6d 5f 73 65 63 } //1 .vm_sec
		$a_01_2 = {2e 74 68 65 6d 69 64 61 } //1 .themida
		$a_01_3 = {43 00 68 00 6f 00 2d 00 43 00 68 00 75 00 6e 00 20 00 48 00 75 00 61 00 6e 00 67 00 } //1 Cho-Chun Huang
		$a_01_4 = {2f 63 68 65 63 6b 70 72 6f 74 65 63 74 69 6f 6e } //1 /checkprotection
		$a_01_5 = {65 00 2d 00 43 00 68 00 69 00 6e 00 61 00 20 00 50 00 65 00 74 00 72 00 6f 00 6c 00 65 00 75 00 6d 00 20 00 26 00 20 00 43 00 68 00 65 00 6d 00 69 00 63 00 61 00 6c 00 20 00 43 00 6f 00 72 00 70 00 } //1 e-China Petroleum & Chemical Corp
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win32_AgentTesla_A_MTB_3{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 51 fa f1 4b 6d ec fb 9f d9 6f 9b ea 37 df 0a 80 13 27 4e fa a3 a0 96 47 d9 8b d6 a9 75 17 02 40 3d a9 37 f5 18 65 2f 1a 03 8d 85 c6 44 63 43 00 a0 22 e5 06 40 4b f3 0e 53 69 e3 d2 91 26 8e da db fe a4 ed de d5 6a cd db 5b ac d0 4f 5b eb 1e ff 7a 1c bd 68 dd 85 3e d4 93 7a 8b a3 97 42 69 6c 0a fd 10 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}