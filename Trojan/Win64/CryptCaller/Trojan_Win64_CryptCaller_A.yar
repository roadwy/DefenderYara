
rule Trojan_Win64_CryptCaller_A{
	meta:
		description = "Trojan:Win64/CryptCaller.A,SIGNATURE_TYPE_PEHSTR_EXT,17 00 14 00 07 00 00 "
		
	strings :
		$a_01_0 = {d8 ec b0 64 28 fc c0 74 } //10
		$a_01_1 = {38 cc 90 44 08 dc a0 54 } //10
		$a_00_2 = {43 00 68 00 61 00 69 00 6e 00 69 00 6e 00 67 00 4d 00 6f 00 64 00 65 00 43 00 42 00 43 00 } //1 ChainingModeCBC
		$a_01_3 = {55 6e 6b 6e 6f 77 6e 20 70 73 65 75 64 6f 20 72 65 6c 6f 63 61 74 69 6f 6e 20 70 72 6f 74 6f 63 6f 6c 20 76 65 72 73 69 6f 6e } //1 Unknown pseudo relocation protocol version
		$a_01_4 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
		$a_01_5 = {42 43 72 79 70 74 47 65 6e 65 72 61 74 65 53 79 6d 6d 65 74 72 69 63 4b 65 79 } //1 BCryptGenerateSymmetricKey
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=20
 
}