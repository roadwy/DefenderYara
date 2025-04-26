
rule Trojan_Win32_Vilsel_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Vilsel.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 0b 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 44 75 63 44 75 6e } //1 C:\Documents and Settings\DucDun
		$a_81_1 = {48 69 64 65 46 69 6c 65 45 78 74 } //1 HideFileExt
		$a_81_2 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 } //1 CreateTextFile
		$a_81_3 = {52 65 67 43 72 65 61 74 65 4b 65 79 41 } //1 RegCreateKeyA
		$a_81_4 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_81_5 = {74 65 6d 70 2e 7a 69 70 } //1 temp.zip
		$a_81_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 6d 73 76 62 76 6d 36 30 2e 64 6c 6c 5c 33 } //1 C:\WINDOWS\system32\msvbvm60.dll\3
		$a_81_7 = {2a 5c 41 44 3a 5c 4c 61 70 20 54 72 69 6e 68 5c 56 69 72 75 73 20 4d 61 75 5c 50 72 6f 20 33 5c 50 72 6f 33 2e 76 62 70 } //10 *\AD:\Lap Trinh\Virus Mau\Pro 3\Pro3.vbp
		$a_81_8 = {2a 5c 41 43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 44 75 63 44 75 6e 67 5c 44 65 73 6b 74 6f 70 5c 50 72 6f 20 33 5c 50 72 6f 33 2e 76 62 70 } //10 *\AC:\Documents and Settings\DucDung\Desktop\Pro 3\Pro3.vbp
		$a_81_9 = {6d 75 73 69 63 2e 65 78 65 } //20 music.exe
		$a_81_10 = {6d 75 73 69 63 76 6e 2e 65 78 65 } //20 musicvn.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*10+(#a_81_8  & 1)*10+(#a_81_9  & 1)*20+(#a_81_10  & 1)*20) >=37
 
}