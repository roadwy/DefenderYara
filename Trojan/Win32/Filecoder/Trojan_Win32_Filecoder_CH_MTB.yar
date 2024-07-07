
rule Trojan_Win32_Filecoder_CH_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 53 74 65 76 65 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 43 72 79 70 74 6f 4c 6f 63 6b 65 72 5c 52 65 6c 65 61 73 65 5c 66 6c 75 66 66 79 2e 70 64 62 } //1 C:\Users\Steve\source\repos\CryptoLocker\Release\fluffy.pdb
		$a_81_1 = {65 6e 63 72 79 70 74 65 64 } //1 encrypted
		$a_81_2 = {67 62 70 56 54 46 39 70 78 6c 42 } //1 gbpVTF9pxlB
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_4 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
		$a_01_5 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
		$a_01_6 = {53 48 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 50 61 74 68 57 } //1 SHGetSpecialFolderPathW
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}