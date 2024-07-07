
rule Trojan_BAT_RedLineStealer_MK_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {13 04 03 8e 69 17 da 13 05 16 13 08 2b 1b 90 02 04 11 04 11 08 08 11 08 08 8e 69 5d 91 03 11 08 91 61 b4 9c 90 02 04 11 08 17 d6 13 08 11 08 11 05 fe 02 16 fe 01 13 09 11 09 2d d6 11 04 13 0a 2b 00 11 0a 2a 90 00 } //1
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {44 61 6e 67 65 72 6f 75 73 47 65 74 48 61 6e 64 6c 65 } //1 DangerousGetHandle
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_5 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_6 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_7 = {61 64 64 5f 4b 65 79 44 6f 77 6e } //1 add_KeyDown
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_RedLineStealer_MK_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_81_0 = {42 4c 4f 57 4a 4f 42 } //1 BLOWJOB
		$a_81_1 = {43 55 4d 53 48 4f 54 } //1 CUMSHOT
		$a_81_2 = {42 55 59 20 43 52 59 50 } //1 BUY CRYP
		$a_81_3 = {40 50 75 6c 73 61 72 43 72 79 70 74 65 72 5f 62 6f 74 } //1 @PulsarCrypter_bot
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_5 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_6 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_7 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64GetThreadContext
		$a_81_8 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 GetThreadContext
		$a_81_9 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_81_10 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_81_11 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_81_12 = {44 79 6e 61 6d 69 63 44 6c 6c 49 6e 76 6f 6b 65 } //1 DynamicDllInvoke
		$a_81_13 = {44 79 6e 61 6d 69 63 44 6c 6c 4d 6f 64 75 6c 65 } //1 DynamicDllModule
		$a_81_14 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=15
 
}
rule Trojan_BAT_RedLineStealer_MK_MTB_3{
	meta:
		description = "Trojan:BAT/RedLineStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4c 00 4c 00 0c 00 00 "
		
	strings :
		$a_80_0 = {2a 2e 77 61 6c 6c 65 74 } //*.wallet  10
		$a_80_1 = {57 61 6c 6c 65 74 40 } //Wallet@  10
		$a_80_2 = {2d 2a 2e 6c 6f 2d 2d 67 } //-*.lo--g  2
		$a_80_3 = {63 6f 6d 2e 6c 69 62 65 72 74 79 2e 6a 61 78 78 } //com.liberty.jaxx  10
		$a_80_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 6f 72 } //SELECT * FROM Win32_Processor  10
		$a_80_5 = {4e 75 6d 62 65 72 4f 66 43 6f 72 65 73 } //NumberOfCores  2
		$a_80_6 = {41 64 61 70 74 65 72 52 41 4d } //AdapterRAM  2
		$a_80_7 = {41 6e 74 71 75 65 69 72 65 73 69 76 69 72 75 73 50 72 6f 64 71 75 65 69 72 65 73 75 63 74 4e } //AntqueiresivirusProdqueiresuctN  2
		$a_80_8 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 56 69 64 65 6f 43 6f 6e 74 72 6f 6c 6c 65 72 } //SELECT * FROM Win32_VideoController  10
		$a_80_9 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //shell\open\command  10
		$a_80_10 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 44 69 73 6b 44 72 69 76 65 } //SELECT * FROM Win32_DiskDrive  10
		$a_80_11 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //SELECT * FROM Win32_OperatingSystem  10
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*10+(#a_80_9  & 1)*10+(#a_80_10  & 1)*10+(#a_80_11  & 1)*10) >=76
 
}