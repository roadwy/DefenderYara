
rule Backdoor_Win32_Bazarldr_DA_MTB{
	meta:
		description = "Backdoor:Win32/Bazarldr.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 70 61 75 73 65 } //5 C:\WINDOWS\system32\cmd.exe /c pause
		$a_81_1 = {61 73 63 76 63 65 76 74 72 68 79 68 6a 74 6a 6b 75 79 62 65 61 76 72 } //5 ascvcevtrhyhjtjkuybeavr
		$a_81_2 = {63 6f 6e 73 6f 6c 65 5f 68 65 6c 6c 6f } //1 console_hello
		$a_81_3 = {41 63 71 75 69 72 65 53 52 57 4c 6f 63 6b 45 78 63 6c 75 73 69 76 65 } //1 AcquireSRWLockExclusive
		$a_81_4 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 61 6c 72 65 61 64 79 20 69 6e 20 70 72 6f 67 72 65 73 73 } //1 connection already in progress
		$a_81_5 = {73 74 72 69 6e 67 20 74 6f 6f 20 6c 6f 6e 67 } //1 string too long
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=14
 
}