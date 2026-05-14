
rule Trojan_Win64_Vimditator_SS_MTB{
	meta:
		description = "Trojan:Win64/Vimditator.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 49 6e 73 74 61 6c 6c 50 65 72 73 69 73 74 65 6e 63 65 } //1 main.InstallPersistence
		$a_01_1 = {6d 61 69 6e 2e 52 65 6d 6f 76 65 50 65 72 73 69 73 74 65 6e 63 65 } //1 main.RemovePersistence
		$a_01_2 = {6d 61 69 6e 2e 4e 65 77 52 65 73 69 6c 69 65 6e 74 45 78 65 63 75 74 6f 72 } //1 main.NewResilientExecutor
		$a_01_3 = {6d 61 69 6e 2e 28 2a 54 61 73 6b 45 78 65 63 75 74 6f 72 29 2e 65 78 65 63 75 74 65 50 65 72 73 69 73 74 65 6e 63 65 } //1 main.(*TaskExecutor).executePersistence
		$a_01_4 = {73 79 73 63 61 6c 6c 2e 28 2a 4c 61 7a 79 44 4c 4c 29 2e 4e 65 77 50 72 6f 63 } //1 syscall.(*LazyDLL).NewProc
		$a_01_5 = {6d 61 69 6e 2e 70 6b 63 73 37 50 61 64 } //1 main.pkcs7Pad
		$a_01_6 = {6d 61 69 6e 2e 28 2a 54 61 73 6b 45 78 65 63 75 74 6f 72 29 2e 65 78 65 63 75 74 65 43 6c 65 61 6e 75 70 } //1 main.(*TaskExecutor).executeCleanup
		$a_01_7 = {6d 61 69 6e 2e 4e 65 77 54 61 73 6b 45 78 65 63 75 74 6f 72 } //1 main.NewTaskExecutor
		$a_01_8 = {6d 61 69 6e 2e 28 2a 52 65 73 69 6c 69 65 6e 74 45 78 65 63 75 74 6f 72 29 2e 47 65 74 43 75 72 72 65 6e 74 55 52 4c } //1 main.(*ResilientExecutor).GetCurrentURL
		$a_01_9 = {6d 61 69 6e 2e 28 2a 54 61 73 6b 45 78 65 63 75 74 6f 72 29 2e 65 78 65 63 75 74 65 53 68 65 6c 6c } //1 main.(*TaskExecutor).executeShell
		$a_01_10 = {6d 61 69 6e 2e 28 2a 43 6f 6e 6e 65 63 74 69 6f 6e 4d 61 6e 61 67 65 72 29 2e 47 65 74 53 6c 65 65 70 44 75 72 61 74 69 6f 6e } //1 main.(*ConnectionManager).GetSleepDuration
		$a_01_11 = {6d 61 69 6e 2e 64 65 72 69 76 65 4b 65 79 } //1 main.deriveKey
		$a_01_12 = {6d 61 69 6e 2e 67 65 74 43 32 55 52 4c } //1 main.getC2URL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}