
rule Trojan_Win32_Stelega_RMA_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 09 00 00 "
		
	strings :
		$a_81_0 = {53 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 57 } //1 SetCurrentDirectoryW
		$a_81_1 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 57 } //1 OutputDebugStringW
		$a_81_2 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_81_3 = {5c 6d 61 69 6c 73 6c 6f 74 } //1 \mailslot
		$a_81_4 = {51 30 36 4e 71 6b 6d 4e 6e 69 46 41 32 39 50 39 63 31 34 50 46 74 71 33 69 74 56 44 55 4d 6f 4b 4c 58 49 61 35 55 58 6d 7a 46 } //10 Q06NqkmNniFA29P9c14PFtq3itVDUMoKLXIa5UXmzF
		$a_81_5 = {70 54 46 45 48 76 7a 5a 4e 72 39 69 53 52 34 53 49 45 50 6b 30 68 48 63 4b 4c 35 46 48 4a 36 33 6e 67 51 71 38 38 50 68 50 4a 62 } //10 pTFEHvzZNr9iSR4SIEPk0hHcKL5FHJ63ngQq88PhPJb
		$a_81_6 = {65 66 46 56 55 36 75 49 63 4f 4c 54 37 56 45 4a 42 77 79 67 71 74 5a 55 55 75 79 30 7a 38 61 33 4c 34 66 50 33 58 4f 76 6f 6c 50 37 47 55 71 30 6b } //10 efFVU6uIcOLT7VEJBwygqtZUUuy0z8a3L4fP3XOvolP7GUq0k
		$a_81_7 = {78 4c 76 76 54 4a 58 6a 45 42 44 30 72 6f 7a 6b 37 6b 79 38 4b 72 51 73 63 53 4b 5a 36 53 42 6d 4c 61 76 46 61 4d 64 61 71 44 64 } //10 xLvvTJXjEBD0rozk7ky8KrQscSKZ6SBmLavFaMdaqDd
		$a_81_8 = {6d 51 38 34 61 5a 49 4a 74 6b 6b 37 44 38 75 78 75 4a 45 32 79 52 64 31 62 64 6e 47 65 6f 4e 66 4f 6a 42 33 } //10 mQ84aZIJtkk7D8uxuJE2yRd1bdnGeoNfOjB3
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10+(#a_81_7  & 1)*10+(#a_81_8  & 1)*10) >=14
 
}