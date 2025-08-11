
rule Trojan_Win64_Stealer_NR_MTB{
	meta:
		description = "Trojan:Win64/Stealer.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0c 00 00 "
		
	strings :
		$a_01_0 = {73 74 65 61 6c 57 6f 72 6b } //2 stealWork
		$a_01_1 = {50 72 6f 63 53 74 65 61 6c } //2 ProcSteal
		$a_01_2 = {68 61 6e 67 75 70 6b 69 6c 6c 65 64 6c 69 73 74 65 6e 73 6f 63 6b 65 74 } //1 hangupkilledlistensocket
		$a_01_3 = {6b 69 6c 6c 69 6e 67 20 43 6d 64 65 78 65 } //1 killing Cmdexe
		$a_01_4 = {64 65 73 74 72 6f 79 } //1 destroy
		$a_01_5 = {62 61 64 20 72 65 73 74 61 72 74 20 50 43 } //1 bad restart PC
		$a_01_6 = {47 65 74 55 73 65 72 50 72 6f 66 69 6c 65 44 69 72 65 63 74 6f 72 79 } //1 GetUserProfileDirectory
		$a_01_7 = {42 6f 74 2f 4e 65 77 2f 4c 61 75 6e 63 68 65 72 } //1 Bot/New/Launcher
		$a_01_8 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //1 GetSystemInfo
		$a_01_9 = {73 61 76 65 49 6e 66 6f 46 72 6f 6d 50 61 74 68 } //1 saveInfoFromPath
		$a_01_10 = {74 61 72 67 65 74 70 63 } //1 targetpc
		$a_01_11 = {72 65 6d 6f 74 65 20 61 64 64 72 65 73 73 20 63 68 61 6e 67 65 64 } //1 remote address changed
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=14
 
}