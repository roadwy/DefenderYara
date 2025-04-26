
rule Trojan_Win64_Stealer_WZ_MTB{
	meta:
		description = "Trojan:Win64/Stealer.WZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {72 75 6e 74 69 6d 65 2e 73 74 65 61 6c 57 6f 72 6b } //1 runtime.stealWork
		$a_81_1 = {2f 44 65 73 6b 74 6f 70 2f 53 74 65 61 6c 65 72 2f 6d 61 69 6e 2e 67 6f } //1 /Desktop/Stealer/main.go
		$a_01_2 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 } //1 Go build ID: 
		$a_81_3 = {68 31 3a 48 2b 74 36 41 2f 51 4a 4d 62 68 43 53 45 48 35 72 41 75 52 78 68 2b 43 74 57 39 36 67 30 4f 72 30 46 78 61 39 49 4b 72 34 75 63 3d } //1 h1:H+t6A/QJMbhCSEH5rAuRxh+CtW96g0Or0Fxa9IKr4uc=
		$a_81_4 = {6d 61 69 6e 2e 72 65 76 65 72 73 65 53 74 72 69 6e 67 } //1 main.reverseString
		$a_81_5 = {74 79 70 65 3a 2e 65 71 2e 6d 61 69 6e 2e 52 65 73 70 6f 6e 73 65 } //1 type:.eq.main.Response
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}