
rule Trojan_Win32_Stealer_MA_MTB{
	meta:
		description = "Trojan:Win32/Stealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 2b c7 89 45 08 8b 45 0c 8d 48 01 8a 10 40 84 d2 75 90 01 01 2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8d 0c 3e 8a 04 02 8b 55 08 32 04 0a 46 88 01 3b 75 10 72 90 00 } //1
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
		$a_01_3 = {4c 6f 63 6b 46 69 6c 65 45 78 } //1 LockFileEx
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}