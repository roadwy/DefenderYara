
rule Trojan_Win64_RedDelta_DA_MTB{
	meta:
		description = "Trojan:Win64/RedDelta.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 48 52 30 63 44 6f 76 4c 32 5a 73 59 58 4e 6f 64 58 42 6b 59 58 52 6c 5a 43 35 6a 62 32 30 36 4f 44 41 77 4d 51 } //1 aHR0cDovL2ZsYXNodXBkYXRlZC5jb206ODAwMQ
		$a_81_1 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1 ReflectiveLoader
		$a_81_2 = {42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 } //1 BEGIN PUBLIC KEY
		$a_81_3 = {43 52 59 50 54 5f 45 5f 52 45 56 4f 4b 45 44 } //1 CRYPT_E_REVOKED
		$a_81_4 = {44 62 67 55 69 53 74 6f 70 44 65 62 75 67 67 69 6e 67 } //1 DbgUiStopDebugging
		$a_81_5 = {43 4c 52 4c 6f 61 64 65 72 2e 65 78 65 } //1 CLRLoader.exe
		$a_81_6 = {66 6c 61 63 68 2e 70 68 70 } //1 flach.php
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}