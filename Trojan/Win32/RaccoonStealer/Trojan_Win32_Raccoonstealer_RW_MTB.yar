
rule Trojan_Win32_Raccoonstealer_RW_MTB{
	meta:
		description = "Trojan:Win32/Raccoonstealer.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 43 4f 44 41 46 36 } //1 C:\Windows\system32\CODAF6
		$a_81_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 43 4f 44 45 4a 4f } //1 C:\Windows\system32\CODEJO
		$a_81_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 43 4f 44 44 32 35 } //1 C:\Windows\system32\CODD25
		$a_81_3 = {72 65 72 6d 66 63 73 65 64 61 77 61 64 37 37 37 65 6d 75 69 78 } //1 rermfcsedawad777emuix
		$a_81_4 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 57 } //1 CryptAcquireContextW
		$a_81_5 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_81_6 = {52 65 67 4f 70 65 6e 4b 65 79 45 78 57 } //1 RegOpenKeyExW
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}