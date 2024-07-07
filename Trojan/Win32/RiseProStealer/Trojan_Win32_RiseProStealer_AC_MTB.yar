
rule Trojan_Win32_RiseProStealer_AC_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f be c9 8d 52 01 33 ce 69 f1 93 01 00 01 8a 4a ff 84 c9 } //2
		$a_01_1 = {65 79 41 69 64 48 6c 77 49 6a 6f 67 49 6b 70 58 56 43 49 73 49 43 4a 68 62 47 63 69 4f 69 41 69 52 57 52 45 55 30 45 69 49 48 30 } //2 eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0
		$a_01_2 = {52 69 73 65 50 72 6f 53 55 50 50 4f 52 54 } //2 RiseProSUPPORT
		$a_81_3 = {65 79 41 69 64 48 6c 77 49 6a 6f 67 49 6b 70 58 56 43 49 73 49 43 4a 68 62 47 63 69 4f 69 41 69 52 57 52 45 55 30 45 69 49 48 30 2e } //1 eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.
		$a_81_4 = {6c 61 7a 65 72 79 6f 75 6e 67 74 68 75 67 } //1 lazeryoungthug
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}