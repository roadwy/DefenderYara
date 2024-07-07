
rule Backdoor_Win32_Sarveci_A{
	meta:
		description = "Backdoor:Win32/Sarveci.A,SIGNATURE_TYPE_PEHSTR,35 00 35 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 4b 61 76 2e 6b 65 79 } //1 \Kav.key
		$a_01_1 = {4e 42 5f 53 65 72 76 65 72 5f 55 70 64 61 74 65 } //1 NB_Server_Update
		$a_01_2 = {4a 69 6e 73 68 61 6e 5f 6c 6a } //1 Jinshan_lj
		$a_01_3 = {53 65 72 76 69 63 65 41 56 33 } //1 ServiceAV3
		$a_01_4 = {5b 25 64 2f 25 64 2f 25 64 20 25 64 3a 25 64 3a 25 64 5d 20 28 25 73 29 } //10 [%d/%d/%d %d:%d:%d] (%s)
		$a_01_5 = {6d 49 43 52 4f 53 4f 46 54 5c 6e 45 54 57 4f 52 4b 5c 63 4f 4e 4e 45 43 54 49 4f 4e 53 5c 50 42 4b 5c 52 41 53 50 48 4f 4e 45 2e 50 42 4b } //10 mICROSOFT\nETWORK\cONNECTIONS\PBK\RASPHONE.PBK
		$a_01_6 = {61 50 50 4c 49 43 41 54 49 4f 4e 53 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 5c 53 48 45 4c 4c 5c 4f 50 45 4e 5c 43 4f 4d 4d 41 4e 44 } //10 aPPLICATIONS\IEXPLORE.EXE\SHELL\OPEN\COMMAND
		$a_01_7 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //10 capGetDriverDescriptionA
		$a_01_8 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10) >=53
 
}