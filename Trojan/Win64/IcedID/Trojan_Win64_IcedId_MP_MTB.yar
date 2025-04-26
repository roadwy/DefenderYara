
rule Trojan_Win64_IcedID_MP_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af 56 68 05 24 c2 13 00 01 46 58 48 63 4e 6c 48 8b 86 a8 00 00 00 88 14 01 44 8b 86 e0 00 00 00 8b 96 bc 00 00 00 44 8b 9e 34 01 00 00 8b 9e 18 01 00 00 ff 46 6c 41 8d 48 ed 03 4e 78 09 4e 78 8b 4e 44 8b c1 33 86 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_IcedID_MP_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 6e 73 6a 75 79 61 67 73 64 62 68 6a 6e 67 6a 69 66 6f 6d 61 6a 64 75 61 68 79 } //10 tnsjuyagsdbhjngjifomajduahy
		$a_01_1 = {62 68 75 6e 6e 6e 6e 64 75 61 68 73 64 69 6f 6a 61 73 64 79 67 61 6a 61 6b 73 73 } //10 bhunnnnduahsdiojasdygajakss
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
		$a_01_3 = {43 72 65 61 74 65 45 76 65 6e 74 41 } //2 CreateEventA
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //2 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=16
 
}
rule Trojan_Win64_IcedID_MP_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 15 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //30 PluginInit
		$a_01_1 = {48 69 61 46 37 4f 2e 64 6c 6c } //1 HiaF7O.dll
		$a_01_2 = {50 71 75 73 62 72 73 } //1 Pqusbrs
		$a_01_3 = {50 79 5a 44 65 67 57 } //1 PyZDegW
		$a_01_4 = {57 4a 71 75 76 66 53 45 4f 59 } //1 WJquvfSEOY
		$a_01_5 = {57 64 52 5a 73 48 } //1 WdRZsH
		$a_01_6 = {4b 61 68 36 78 36 35 78 51 2e 64 6c 6c } //1 Kah6x65xQ.dll
		$a_01_7 = {43 4c 72 42 76 59 66 77 48 58 } //1 CLrBvYfwHX
		$a_01_8 = {4a 6b 48 59 49 64 44 73 73 47 } //1 JkHYIdDssG
		$a_01_9 = {4d 6c 4d 62 55 4f 74 49 70 } //1 MlMbUOtIp
		$a_01_10 = {6d 41 6e 4d 46 71 59 44 49 53 4a } //1 mAnMFqYDISJ
		$a_01_11 = {5a 70 47 44 53 41 4c 63 56 6e 2e 64 6c 6c } //1 ZpGDSALcVn.dll
		$a_01_12 = {46 64 67 54 55 57 4c 4d 48 } //1 FdgTUWLMH
		$a_01_13 = {4a 6b 6e 70 6a 46 74 58 77 } //1 JknpjFtXw
		$a_01_14 = {4d 64 77 74 6d 77 71 54 61 58 } //1 MdwtmwqTaX
		$a_01_15 = {68 57 4a 4d 4a 51 71 74 } //1 hWJMJQqt
		$a_01_16 = {45 50 6e 43 4f 5a 4f 63 50 45 2e 64 6c 6c } //1 EPnCOZOcPE.dll
		$a_01_17 = {70 49 71 46 51 51 6f 72 5a 45 70 } //1 pIqFQQorZEp
		$a_01_18 = {77 6f 79 6d 63 74 7a 61 54 6a } //1 woymctzaTj
		$a_01_19 = {4f 4a 5a 53 4d 41 4e 4f 75 6a } //1 OJZSMANOuj
		$a_01_20 = {42 6d 73 45 75 77 46 73 } //1 BmsEuwFs
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1) >=35
 
}