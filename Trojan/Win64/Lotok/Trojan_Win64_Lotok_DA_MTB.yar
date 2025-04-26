
rule Trojan_Win64_Lotok_DA_MTB{
	meta:
		description = "Trojan:Win64/Lotok.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_80_0 = {50 6f 74 65 6e 74 69 61 6c 20 73 61 6e 64 62 6f 78 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 64 65 74 65 63 74 65 64 } //Potential sandbox environment detected  10
		$a_80_1 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 65 78 65 63 75 74 61 62 6c 65 20 6e 61 6d 65 } //Failed to get executable name  1
		$a_80_2 = {4d 69 63 72 6f 73 6f 66 74 45 64 67 65 55 70 64 61 74 65 2e 65 78 65 } //MicrosoftEdgeUpdate.exe  10
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_4 = {50 65 4c 6f 61 64 65 72 45 72 72 } //PeLoaderErr  1
		$a_80_5 = {50 65 50 61 72 73 65 72 45 72 72 } //PeParserErr  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=24
 
}