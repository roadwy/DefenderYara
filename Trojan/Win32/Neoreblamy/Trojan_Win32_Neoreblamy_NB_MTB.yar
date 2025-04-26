
rule Trojan_Win32_Neoreblamy_NB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {42 46 7a 53 77 55 67 4f 75 65 79 78 6c 68 56 75 67 6e 58 6e 6d 58 41 4c 65 44 75 65 6a 46 4a 46 42 71 } //2 BFzSwUgOueyxlhVugnXnmXALeDuejFJFBq
		$a_81_1 = {6a 73 72 42 48 47 74 4f 4e 4c 6e 75 6b 6d 63 77 52 71 53 43 72 57 } //1 jsrBHGtONLnukmcwRqSCrW
		$a_81_2 = {59 67 69 75 72 52 48 64 6f 67 4c 45 78 6b 44 48 57 63 72 50 43 72 77 4b 67 52 53 5a 50 47 61 4f 5a 59 6a 71 78 78 67 61 72 } //1 YgiurRHdogLExkDHWcrPCrwKgRSZPGaOZYjqxxgar
		$a_81_3 = {47 48 52 6d 66 73 75 73 4e 4f 6c 44 5a 64 4a 47 63 45 54 6e 64 69 54 59 49 6d 47 69 78 7a 5a 62 4c 59 4f 53 6d 51 46 67 4e 79 66 } //1 GHRmfsusNOlDZdJGcETndiTYImGixzZbLYOSmQFgNyf
		$a_81_4 = {6d 46 70 55 4c 49 43 47 74 53 51 62 59 62 45 44 78 4f 66 4a 4d 77 78 75 77 42 63 65 48 77 61 50 66 75 7a 5a 6d 61 6d 4f 45 6b 72 } //1 mFpULICGtSQbYbEDxOfJMwxuwBceHwaPfuzZmamOEkr
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}