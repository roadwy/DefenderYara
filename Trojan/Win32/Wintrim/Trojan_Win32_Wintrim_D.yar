
rule Trojan_Win32_Wintrim_D{
	meta:
		description = "Trojan:Win32/Wintrim.D,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 43 76 32 44 4c 4c 2e 64 6c 6c 00 53 74 61 72 74 4d 43 } //10
		$a_01_1 = {6d 79 6d 75 74 73 67 6c 77 6f 72 6b } //1 mymutsglwork
		$a_01_2 = {43 45 47 43 6f 6d 70 75 74 65 72 49 6e 66 6f 3a 3a 47 65 74 43 6f 6d 70 75 74 65 72 49 44 28 29 } //1 CEGComputerInfo::GetComputerID()
		$a_01_3 = {43 45 47 43 6f 6d 70 75 74 65 72 49 6e 66 6f 3a 3a 47 65 74 57 69 6e 56 65 72 73 69 6f 6e 28 29 } //1 CEGComputerInfo::GetWinVersion()
		$a_01_4 = {4d 43 5f 55 50 44 41 54 45 } //1 MC_UPDATE
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 6d 63 } //1 Software\mc
		$a_01_6 = {4e 61 76 54 69 6d 65 20 69 73 20 6f 76 65 72 2e } //1 NavTime is over.
		$a_01_7 = {52 65 6d 6f 74 65 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 20 65 72 72 6f 72 } //1 RemoteDownloadFile error
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=15
 
}