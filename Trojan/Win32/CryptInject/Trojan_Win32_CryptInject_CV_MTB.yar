
rule Trojan_Win32_CryptInject_CV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 6d 68 68 64 6e 6c 68 55 32 39 6d 64 48 64 68 63 6d 56 7a 5c 6e 6f 64 65 5c 6e 6f 64 65 2e 65 78 65 } //01 00  QmhhdnlhU29mdHdhcmVz\node\node.exe
		$a_01_1 = {51 6d 68 68 64 6e 6c 68 55 32 39 6d 64 48 64 68 63 6d 56 7a 5c 73 65 72 76 65 72 2e 6a 73 } //01 00  QmhhdnlhU29mdHdhcmVz\server.js
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00  QueryPerformanceCounter
	condition:
		any of ($a_*)
 
}