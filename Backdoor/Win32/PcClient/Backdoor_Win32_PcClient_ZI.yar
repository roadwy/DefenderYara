
rule Backdoor_Win32_PcClient_ZI{
	meta:
		description = "Backdoor:Win32/PcClient.ZI,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e8 2e c6 45 e9 73 c6 45 ea 79 c6 45 eb 73 c6 45 d8 64 c6 45 d9 72 c6 45 da 69 c6 45 db 76 c6 45 dc 65 c6 45 dd 72 c6 45 de 73 } //1
		$a_01_1 = {c6 45 84 6f c6 45 87 74 c6 45 e8 2e c6 45 e9 74 c6 45 ea 6d c6 45 eb 70 } //1
		$a_01_2 = {c6 45 84 64 c6 45 87 69 c6 45 e8 2e c6 45 e9 64 c6 45 ea 6c c6 45 eb 6c } //1
		$a_01_3 = {c6 45 84 73 c6 45 87 70 c6 45 e8 2e c6 45 e9 74 c6 45 ea 6d c6 45 eb 70 } //1
		$a_01_4 = {c6 45 84 7a c6 45 87 61 c6 45 e8 2e c6 45 e9 74 c6 45 ea 6d c6 45 eb 70 } //1
		$a_01_5 = {c6 45 e0 25 c6 45 e1 73 c6 45 e2 5c c6 45 e3 25 c6 45 e4 73 c6 45 e5 2e c6 45 e6 65 c6 45 e7 78 c6 45 e8 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}