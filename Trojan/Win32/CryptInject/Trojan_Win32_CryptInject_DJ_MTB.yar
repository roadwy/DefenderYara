
rule Trojan_Win32_CryptInject_DJ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {2b f7 33 f1 81 e6 [0-04] 33 f1 8b 4a 08 89 71 04 8b 52 0c 85 d2 75 a2 } //2
		$a_01_1 = {6d 73 6f 63 78 75 73 79 73 2e 64 6c 6c } //1 msocxusys.dll
		$a_01_2 = {73 6e 78 61 70 69 2e 65 78 65 } //1 snxapi.exe
		$a_01_3 = {45 6e 63 72 79 70 74 } //1 Encrypt
		$a_01_4 = {73 67 76 72 66 79 33 32 2e 65 78 65 } //1 sgvrfy32.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}