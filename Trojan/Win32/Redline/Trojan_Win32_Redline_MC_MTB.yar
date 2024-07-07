
rule Trojan_Win32_Redline_MC_MTB{
	meta:
		description = "Trojan:Win32/Redline.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 2f 47 e2 90 0a 37 00 f6 17 90 01 18 80 07 90 01 01 80 2f 90 01 13 f6 2f 47 e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 12 00 00 00 c7 45 fc ff ff ff ff 8b 75 0c 8b 45 e8 03 f0 33 d2 f7 75 14 8b 45 08 8a 04 02 8a c8 02 c0 02 c8 c0 e1 05 30 0e ff 45 e8 e9 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_MC_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 75 41 46 47 73 79 47 73 68 41 73 74 75 36 37 38 65 32 38 72 } //10 huAFGsyGshAstu678e28r
		$a_03_1 = {0f b6 4d d7 8b 45 d8 33 d2 be 04 00 00 00 f7 f6 0f b6 92 90 01 04 33 ca 88 4d df 8b 45 d8 8a 88 90 01 04 88 4d d6 0f b6 55 df 8b 45 d8 0f b6 88 90 01 04 03 ca 8b 55 d8 88 8a 90 01 04 68 90 00 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}
rule Trojan_Win32_Redline_MC_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 ea 05 03 54 24 1c c1 e1 04 03 4c 24 20 03 c3 33 d1 33 d0 2b f2 8b ce c1 e1 04 c7 05 90 01 08 89 4c 24 10 8b 44 24 24 01 44 24 10 81 3d 90 01 04 be 01 00 00 8d 3c 33 75 90 00 } //5
		$a_03_1 = {8b c6 c1 e8 05 03 c5 33 c7 31 44 24 10 c7 05 90 01 08 c7 05 90 01 08 8b 44 24 10 29 44 24 14 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win32_Redline_MC_MTB_5{
	meta:
		description = "Trojan:Win32/Redline.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {71 73 6a 61 6d 63 6c 79 68 69 6c 79 76 6d 72 6a 79 6e 6b 72 71 66 6c 62 79 65 77 66 73 65 76 6e 67 62 78 65 72 79 7a 7a 63 62 6e 71 63 62 6e 75 6e 76 79 6c 7a 6a 77 76 6a 74 78 64 6e 6b 6a 76 73 70 74 } //1 qsjamclyhilyvmrjynkrqflbyewfsevngbxeryzzcbnqcbnunvylzjwvjtxdnkjvspt
		$a_01_1 = {65 78 71 68 6c 74 6a 76 75 79 62 71 61 6e 6a 6e 6b 69 75 79 63 6f 6e 6a 6b } //1 exqhltjvuybqanjnkiuyconjk
		$a_01_2 = {67 61 78 78 69 6e 65 6a 64 77 69 66 62 65 78 63 78 72 74 66 64 63 67 61 66 79 73 78 78 71 7a 6f 73 77 } //1 gaxxinejdwifbexcxrtfdcgafysxxqzosw
		$a_01_3 = {76 79 76 67 6c 68 78 64 71 78 75 6d 63 6e 6c 79 70 64 6c 77 62 74 72 72 68 69 68 65 63 79 62 66 61 6d 77 66 74 67 7a 74 75 70 76 7a 70 7a 78 65 75 74 76 6e } //1 vyvglhxdqxumcnlypdlwbtrrhihecybfamwftgztupvzpzxeutvn
		$a_01_4 = {6a 76 61 69 6a 6c 7a 73 6e 69 61 6d 72 75 6d 6b 75 6c 77 79 79 75 6e 71 74 6d 62 6e 72 6d 6a 6c 77 79 64 6e 6e 66 73 79 68 66 72 6d 71 73 67 74 75 6c 6d 6d 71 67 6d 79 61 7a 6c 7a 61 65 } //1 jvaijlzsniamrumkulwyyunqtmbnrmjlwydnnfsyhfrmqsgtulmmqgmyazlzae
		$a_01_5 = {66 66 6b 75 72 6e 6d 70 73 75 75 63 6b 70 65 6b 68 76 7a 76 6b 6b 71 67 64 62 66 72 6e 66 74 6c 6d 71 63 63 74 6f 78 79 71 6e 63 67 65 69 } //1 ffkurnmpsuuckpekhvzvkkqgdbfrnftlmqcctoxyqncgei
		$a_01_6 = {63 7a 65 7a 73 6e 6a 72 77 6b 65 6a 7a 71 78 70 6c 69 61 73 6d 61 71 74 71 74 79 65 68 63 68 6b 6e 6b 77 71 74 67 6d 77 61 79 64 61 61 } //1 czezsnjrwkejzqxpliasmaqtqtyehchknkwqtgmwaydaa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}