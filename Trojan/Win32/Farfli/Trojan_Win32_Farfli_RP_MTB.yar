
rule Trojan_Win32_Farfli_RP_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6c 6f 67 6f 2e 63 63 6f } //10 C:\Users\Public\Documents\logo.cco
		$a_01_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 5c 00 6c 00 6f 00 67 00 6f 00 2e 00 63 00 63 00 6f 00 } //10 C:\Users\Public\Documents\logo.cco
		$a_01_2 = {50 61 72 61 6c 6c 65 6c 73 20 53 6f 66 74 77 61 72 65 20 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 20 49 6e 63 2e } //1 Parallels Software International Inc.
		$a_01_3 = {69 6e 6e 6f 74 65 6b 20 47 6d 62 48 } //1 innotek GmbH
		$a_01_4 = {4d 69 63 72 6f 73 6f 66 74 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Microsoft Corporation
		$a_01_5 = {56 4d 77 61 72 65 } //1 VMware
		$a_01_6 = {46 61 69 6c 65 64 20 74 6f 20 71 75 65 72 79 20 76 61 6c 75 65 3a 20 53 79 73 74 65 6d 4d 61 6e 75 66 61 63 74 75 72 65 72 } //1 Failed to query value: SystemManufacturer
		$a_01_7 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 42 49 4f 53 } //1 HARDWARE\DESCRIPTION\System\BIOS
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=26
 
}
rule Trojan_Win32_Farfli_RP_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffa5 00 ffffffa5 00 0c 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 69 6e 78 2e 63 6f 64 } //100 C:\Users\inx.cod
		$a_01_1 = {77 6d 69 63 20 62 69 6f 73 20 67 65 74 20 6d 61 6e 75 66 61 63 74 75 72 65 72 } //10 wmic bios get manufacturer
		$a_01_2 = {56 4d 77 61 72 65 } //10 VMware
		$a_01_3 = {56 69 72 74 75 61 6c } //10 Virtual
		$a_01_4 = {4d 69 63 72 6f 73 6f 66 74 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //10 Microsoft Corporation
		$a_01_5 = {69 6e 6e 6f 74 65 6b 20 47 6d 62 48 } //10 innotek GmbH
		$a_01_6 = {50 61 72 61 6c 6c 65 6c 73 20 53 6f 66 74 77 61 72 65 20 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 20 49 6e 63 2e } //10 Parallels Software International Inc.
		$a_01_7 = {5c 56 43 5c 69 6e 63 6c 75 64 65 5c 73 74 72 65 61 6d 62 75 66 } //1 \VC\include\streambuf
		$a_01_8 = {43 00 3a 00 5c 00 49 00 4e 00 54 00 45 00 52 00 4e 00 41 00 4c 00 5c 00 52 00 45 00 4d 00 4f 00 54 00 45 00 2e 00 45 00 58 00 45 00 } //1 C:\INTERNAL\REMOTE.EXE
		$a_01_9 = {73 00 74 00 72 00 63 00 61 00 74 00 5f 00 73 00 28 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 2c 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 53 00 69 00 7a 00 65 00 2c 00 20 00 63 00 6d 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 29 00 } //1 strcat_s(CommandLine, CommandLineSize, cmdstring)
		$a_01_10 = {73 00 74 00 72 00 63 00 61 00 74 00 5f 00 73 00 28 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 2c 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 53 00 69 00 7a 00 65 00 2c 00 20 00 22 00 20 00 2f 00 63 00 20 00 22 00 29 00 } //1 strcat_s(CommandLine, CommandLineSize, " /c ")
		$a_01_11 = {73 00 74 00 72 00 63 00 70 00 79 00 5f 00 73 00 28 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 2c 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 53 00 69 00 7a 00 65 00 2c 00 20 00 63 00 6d 00 64 00 65 00 78 00 65 00 29 00 } //1 strcpy_s(CommandLine, CommandLineSize, cmdexe)
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=165
 
}