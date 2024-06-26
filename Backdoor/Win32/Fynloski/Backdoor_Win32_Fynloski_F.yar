
rule Backdoor_Win32_Fynloski_F{
	meta:
		description = "Backdoor:Win32/Fynloski.F,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 55 54 45 58 4e 41 4d 45 } //01 00  MUTEXNAME
		$a_01_1 = {53 45 52 56 44 4e 41 4d 45 } //01 00  SERVDNAME
		$a_01_2 = {41 43 54 49 56 58 4e 41 4d 45 } //01 00  ACTIVXNAME
		$a_01_3 = {41 4e 54 49 56 4d } //01 00  ANTIVM
		$a_01_4 = {4d 45 4c 54 } //01 00  MELT
		$a_01_5 = {47 45 54 4d 53 4e 49 4e 46 4f } //01 00  GETMSNINFO
		$a_01_6 = {23 62 6f 74 43 6f 6d 6d 61 6e 64 25 4d 61 73 73 } //01 00  #botCommand%Mass
		$a_01_7 = {49 6e 59 6f 75 72 41 73 73 } //01 00  InYourAss
		$a_01_8 = {47 65 74 53 49 4e } //01 00  GetSIN
		$a_01_9 = {52 65 6d 6f 74 65 45 72 72 6f 72 45 72 72 6f 72 20 6f 6e 20 6b 69 6c 6c 20 70 72 6f 63 65 73 73 } //01 00  RemoteErrorError on kill process
		$a_01_10 = {52 65 6d 6f 74 65 45 72 72 6f 72 45 72 72 6f 72 20 6f 6e 20 52 75 6e 20 66 69 6c 65 20 61 73 20 61 64 6d 69 6e } //0f 00  RemoteErrorError on Run file as admin
		$a_03_11 = {80 fb 31 75 0d 8d 90 01 02 b8 90 01 04 e8 90 01 04 80 fb 32 75 0d 8d 90 01 02 b8 90 01 04 e8 90 01 04 80 fb 33 75 0d 8d 90 01 02 b8 90 01 04 e8 90 01 04 80 fb 34 75 0d 8d 90 01 02 b8 90 01 04 e8 90 01 04 80 fb 35 75 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}