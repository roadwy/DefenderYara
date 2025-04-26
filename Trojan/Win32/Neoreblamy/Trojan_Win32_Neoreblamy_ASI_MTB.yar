
rule Trojan_Win32_Neoreblamy_ASI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 4e 76 4e 74 6b 7a 63 69 54 57 4f 6d 67 67 69 61 42 49 64 44 41 6c 63 65 51 5a } //1 XNvNtkzciTWOmggiaBIdDAlceQZ
		$a_01_1 = {75 6c 4d 75 61 4b 58 43 5a 4d 6d 46 44 71 7a 54 4a 69 78 42 70 53 56 63 79 41 56 74 76 52 72 49 69 77 59 4a 57 47 50 68 54 47 66 74 6a 51 4c 45 49 59 7a } //1 ulMuaKXCZMmFDqzTJixBpSVcyAVtvRrIiwYJWGPhTGftjQLEIYz
		$a_01_2 = {76 6e 61 65 69 66 46 6d 66 6f 4f 6f 65 45 6d 65 57 74 42 50 6f 48 44 44 50 70 5a 58 50 46 7a } //1 vnaeifFmfoOoeEmeWtBPoHDDPpZXPFz
		$a_01_3 = {55 65 54 64 51 45 6d 43 69 63 43 44 41 45 4b 6b 57 64 71 47 4c 42 62 54 75 50 7a 48 65 63 4a 57 4d 78 4f 73 53 } //1 UeTdQEmCicCDAEKkWdqGLBbTuPzHecJWMxOsS
		$a_01_4 = {56 52 56 5a 63 70 69 66 66 73 48 41 6e 4e 47 51 46 69 4a 42 52 4c 63 6e 61 6f 5a 77 46 64 43 42 6b 65 } //1 VRVZcpiffsHAnNGQFiJBRLcnaoZwFdCBke
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}