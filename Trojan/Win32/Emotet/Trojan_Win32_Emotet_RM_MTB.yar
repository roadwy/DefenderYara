
rule Trojan_Win32_Emotet_RM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {48 63 66 79 76 67 4f 68 62 76 67 } //HcfyvgOhbvg  1
		$a_80_1 = {59 79 76 67 4b 62 75 76 67 79 } //YyvgKbuvgy  1
		$a_80_2 = {57 78 64 74 63 66 76 67 4f 6e 6a 6b 68 62 6a 67 } //WxdtcfvgOnjkhbjg  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {73 26 70 57 31 56 42 56 4d 62 61 38 45 40 72 25 55 56 5f 6d 6a 31 47 24 32 59 4f 4c 53 51 2b 4c 6a 43 } //s&pW1VBVMba8E@r%UV_mj1G$2YOLSQ+LjC  1
		$a_03_1 = {81 c9 00 10 00 00 51 8b 45 ?? 50 6a 00 6a ff ff 15 ?? ?? ?? ?? 89 45 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_RM_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {58 3e 4a 54 51 28 44 6b 54 25 78 6b 48 5e 38 4a 70 52 40 40 38 77 58 6a 79 68 5a 6f 79 44 45 46 37 67 23 31 6b 4c 44 70 6d 32 33 70 41 49 32 75 6c 77 77 79 65 56 } //X>JTQ(DkT%xkH^8JpR@@8wXjyhZoyDEF7g#1kLDpm23pAI2ulwwyeV  1
		$a_03_1 = {68 00 30 00 00 8b 45 ?? 50 6a 00 6a ff ff } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_RM_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 6e 63 6f 78 6b 6d } //1 ancoxkm
		$a_81_1 = {61 75 6b 6a 62 7a 64 6c 6f 71 71 72 66 76 } //1 aukjbzdloqqrfv
		$a_81_2 = {61 75 78 69 67 75 67 6d 66 74 6e 78 6f } //1 auxigugmftnxo
		$a_81_3 = {63 6b 79 77 65 67 6d 74 6b 76 74 63 73 6e } //1 ckywegmtkvtcsn
		$a_81_4 = {65 71 71 75 64 71 6b 64 76 71 6a 62 78 76 70 77 6d } //1 eqqudqkdvqjbxvpwm
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Emotet_RM_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b f9 57 56 6a 00 6a ff ff 15 ?? ?? ?? ?? e9 } //1
		$a_80_1 = {6d 5f 64 23 35 37 25 35 5a 4e 53 45 31 6e 49 67 69 31 68 26 41 39 3f 39 4a 25 77 66 6f 50 46 6e 72 79 59 40 4a 57 55 40 58 2b 5f 70 78 2a 64 4c 70 25 56 78 43 5f 6f 64 51 3f 32 39 6a 25 76 46 76 39 69 51 5f 53 } //m_d#57%5ZNSE1nIgi1h&A9?9J%wfoPFnryY@JWU@X+_px*dLp%VxC_odQ?29j%vFv9iQ_S  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_RM_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {3c 4d 51 45 75 49 4f 77 47 6c 32 44 7a 23 57 48 51 45 52 34 51 4e 5e 36 24 55 46 23 44 37 59 28 24 28 42 57 6f 75 48 36 71 3c 64 24 77 6c 36 29 51 4c 67 6d 62 39 58 53 4b 77 75 3c 70 6d 23 72 35 4f 3f 41 45 } //<MQEuIOwGl2Dz#WHQER4QN^6$UF#D7Y($(BWouH6q<d$wl6)QLgmb9XSKwu<pm#r5O?AE  1
		$a_03_1 = {81 c9 00 10 00 00 51 56 53 6a ff ff 15 ?? ?? ?? ?? eb ?? 6a 40 68 00 30 00 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}