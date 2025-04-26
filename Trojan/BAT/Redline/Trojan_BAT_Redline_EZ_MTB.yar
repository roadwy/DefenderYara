
rule Trojan_BAT_Redline_EZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 68 67 46 4d 58 67 6d 48 6a 6a 5a 4b 69 44 41 6c 44 59 42 41 74 57 75 4b 52 49 6a } //2 ahgFMXgmHjjZKiDAlDYBAtWuKRIj
		$a_81_1 = {43 6a 47 70 6c 76 4a 74 74 6b 4b 58 7a 7a 55 57 53 4e 63 50 48 6d 44 4c 59 72 73 6b 4f } //2 CjGplvJttkKXzzUWSNcPHmDLYrskO
		$a_81_2 = {6f 41 4d 66 44 56 77 75 71 70 43 6d 4f 4b 59 44 43 49 50 41 53 6e 71 75 53 } //1 oAMfDVwuqpCmOKYDCIPASnquS
		$a_81_3 = {4b 6b 4b 54 4c 47 78 6d 78 68 43 74 77 57 58 62 77 6f 7a 7a 70 4a 4b 70 59 61 78 64 } //1 KkKTLGxmxhCtwWXbwozzpJKpYaxd
		$a_81_4 = {6d 4c 6b 72 70 45 65 7a 43 56 54 4e 76 57 4f 52 59 76 51 62 57 56 4b 43 } //1 mLkrpEezCVTNvWORYvQbWVKC
		$a_81_5 = {46 6d 6e 6b 70 73 61 4a 4e 6a 4c 59 68 51 5a 59 53 63 4f 52 53 74 64 52 49 4f 72 6b 4d } //1 FmnkpsaJNjLYhQZYScORStdRIOrkM
		$a_81_6 = {70 43 50 4b 76 71 47 5a 57 4a 55 61 57 4f 55 75 4d 73 74 41 6e 6e 64 61 57 64 52 } //1 pCPKvqGZWJUaWOUuMstAnndaWdR
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=9
 
}
rule Trojan_BAT_Redline_EZ_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {52 73 4e 51 79 50 6e 56 4f 75 4b 6a 6d 6e 6c 4e 4c 45 49 52 76 66 47 6d 6a 64 4f 70 } //1 RsNQyPnVOuKjmnlNLEIRvfGmjdOp
		$a_81_1 = {56 42 78 56 6f 62 44 49 57 56 4d 53 7a 4e 48 72 55 4c 4f 5a 67 52 2e 64 6c 6c } //1 VBxVobDIWVMSzNHrULOZgR.dll
		$a_81_2 = {4b 69 75 78 41 41 4b 5a 65 72 79 69 44 42 4f 4d 4a 69 59 4c 45 } //1 KiuxAAKZeryiDBOMJiYLE
		$a_81_3 = {47 4f 77 76 67 72 62 74 49 76 77 77 41 68 58 61 55 48 58 6a 59 68 77 71 56 } //1 GOwvgrbtIvwwAhXaUHXjYhwqV
		$a_81_4 = {4f 48 59 4d 6a 43 48 46 56 52 4c 79 55 58 53 6c 67 71 6b 46 4c 67 44 74 78 65 54 69 77 2e 64 6c 6c } //1 OHYMjCHFVRLyUXSlgqkFLgDtxeTiw.dll
		$a_81_5 = {4d 6a 59 42 56 79 6a 65 64 43 6f 6b 77 47 6a 46 72 6f 75 54 56 62 51 } //1 MjYBVyjedCokwGjFrouTVbQ
		$a_81_6 = {30 39 62 38 61 62 31 64 2d 39 61 35 35 2d 34 65 32 38 2d 62 37 31 65 2d 33 36 62 66 35 65 64 37 61 37 39 61 } //1 09b8ab1d-9a55-4e28-b71e-36bf5ed7a79a
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}