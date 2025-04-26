
rule Trojan_Win64_IcedID_DJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0c 00 00 "
		
	strings :
		$a_01_0 = {33 33 6c 4e 30 6d 2e 64 6c 6c } //10 33lN0m.dll
		$a_01_1 = {44 6a 62 72 56 6f 55 79 53 49 } //1 DjbrVoUySI
		$a_01_2 = {50 52 65 62 72 73 51 4e 4f 4a 6d } //1 PRebrsQNOJm
		$a_01_3 = {57 4b 6f 4a 70 74 4d 75 44 44 6d } //1 WKoJptMuDDm
		$a_01_4 = {6c 43 71 42 64 65 7a 35 76 75 2e 64 6c 6c } //10 lCqBdez5vu.dll
		$a_01_5 = {42 58 64 41 69 78 43 6d 4b 53 } //1 BXdAixCmKS
		$a_01_6 = {4f 4e 6f 6c 4e 6f 62 6c 71 5a } //1 ONolNoblqZ
		$a_01_7 = {50 59 44 45 6b 6e 4f 6d 71 4e } //1 PYDEknOmqN
		$a_01_8 = {47 59 73 6e 47 74 73 6f 43 71 2e 64 6c 6c } //10 GYsnGtsoCq.dll
		$a_01_9 = {4c 71 49 56 41 50 6f 54 5a } //1 LqIVAPoTZ
		$a_01_10 = {64 6f 46 4e 48 44 43 77 73 63 } //1 doFNHDCwsc
		$a_01_11 = {72 61 69 62 42 50 5a 73 70 76 58 } //1 raibBPZspvX
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*10+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=13
 
}