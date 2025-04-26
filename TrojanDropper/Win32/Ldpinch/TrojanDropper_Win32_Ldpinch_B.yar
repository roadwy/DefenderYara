
rule TrojanDropper_Win32_Ldpinch_B{
	meta:
		description = "TrojanDropper:Win32/Ldpinch.B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 81 39 4d 5a 75 0d 8b 41 3c 03 c1 81 38 50 45 00 00 74 02 33 c0 } //1
		$a_01_1 = {43 3a 5c 54 45 4d 50 5c 30 38 30 30 2e 74 6d 70 } //1 C:\TEMP\0800.tmp
		$a_01_2 = {57 69 6e 6c 6f 67 6f 6e 44 4c 4c 2e 64 6c 6c } //1 WinlogonDLL.dll
		$a_01_3 = {13 a1 05 c2 57 c0 6b 91 57 c0 6b 91 57 c0 6b 91 d4 c8 36 91 54 c0 6b 91 57 c0 6a 91 5d c0 6b 91 52 cc 0b 91 55 c0 6b 91 52 cc 31 91 56 c0 6b 91 } //1
		$a_01_4 = {ed 28 a5 99 ed 28 a5 99 ed 28 a5 99 ec 28 a5 99 6e 20 f8 99 ee 28 a5 99 ed 28 a4 99 e5 28 a5 99 e8 24 c5 99 e8 28 a5 99 e8 24 f9 99 ec 28 a5 99 e8 24 ff 99 ec 28 a5 99 52 69 63 68 ed 28 a5 99 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}