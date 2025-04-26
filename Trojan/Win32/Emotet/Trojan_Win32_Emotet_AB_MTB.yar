
rule Trojan_Win32_Emotet_AB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {26 68 41 6f 76 54 46 6c 77 2b 66 33 55 46 41 23 29 21 79 52 73 66 4f 45 65 6b 23 53 4e 3f 75 6e 69 38 32 31 } //3 &hAovTFlw+f3UFA#)!yRsfOEek#SN?uni821
		$a_81_1 = {50 6f 73 74 51 75 69 74 4d 65 73 73 61 67 65 } //3 PostQuitMessage
		$a_81_2 = {50 6f 73 74 4d 65 73 73 61 67 65 57 } //3 PostMessageW
		$a_81_3 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //3 NoNetConnectDisconnect
		$a_81_4 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //3 NoRecentDocsHistory
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}
rule Trojan_Win32_Emotet_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 f1 ed b5 77 61 89 45 ?? 8b 45 ?? 8b 55 ?? 8a 1c 02 8b 45 ?? 88 5d ?? 39 c8 74 } //1
		$a_02_1 = {8a 14 01 8b 75 ?? 88 14 06 83 c0 01 8b 7d ?? 39 f8 89 45 ?? 75 90 09 06 00 8b 45 ?? 8b 4d f0 } //1
		$a_02_2 = {81 f1 fb 0d eb 6e 8b 55 ?? 8a 1c 02 8b 75 ?? 88 1c 06 01 c8 8b 4d ?? 39 c8 89 45 ?? 74 } //1
		$a_02_3 = {8a 1c 02 8b 44 24 ?? 88 1c 08 8b 4c 24 ?? 83 c1 01 89 4c 24 ?? 8b 74 24 ?? 39 f1 74 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_AB_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.AB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 2c 8d 04 0a 99 b9 69 7a 00 00 f7 f9 8b 6c 24 54 2b 54 24 14 8b ca 8b 54 24 30 0f b6 } //1
		$a_01_1 = {99 bd 69 7a 00 00 f7 fd 8b 44 24 54 8b 6c 24 18 83 c5 01 89 6c 24 18 03 d7 03 d6 0f b6 14 02 } //1
		$a_01_2 = {70 21 63 21 58 38 3c 30 61 69 52 31 3e 66 6b 64 79 6d 45 3c 58 21 21 78 66 64 74 5a 3f 3c 2a 26 6e 4a 78 52 5a 7a 39 56 6f 79 21 26 71 33 2a 49 54 6b 46 35 37 72 40 5f 45 61 43 4c 7a } //1 p!c!X8<0aiR1>fkdymE<X!!xfdtZ?<*&nJxRZz9Voy!&q3*ITkF57r@_EaCLz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}