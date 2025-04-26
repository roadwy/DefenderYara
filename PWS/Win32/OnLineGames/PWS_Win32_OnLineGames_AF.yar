
rule PWS_Win32_OnLineGames_AF{
	meta:
		description = "PWS:Win32/OnLineGames.AF,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 64 00 61 00 64 00 65 00 66 00 39 00 35 00 35 00 } //2 \Device\dadef955
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 64 00 31 00 30 00 33 00 37 00 61 00 31 00 64 00 } //2 \Device\d1037a1d
		$a_01_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_01_3 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
		$a_01_4 = {5a 77 43 6c 6f 73 65 } //1 ZwClose
		$a_01_5 = {5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 73 00 5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 50 00 61 00 74 00 68 00 } //1 \KnownDlls\KnownDllPath
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}