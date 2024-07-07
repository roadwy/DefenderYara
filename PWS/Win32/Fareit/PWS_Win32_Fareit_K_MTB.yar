
rule PWS_Win32_Fareit_K_MTB{
	meta:
		description = "PWS:Win32/Fareit.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 06 00 00 "
		
	strings :
		$a_02_0 = {b9 77 00 00 00 6a 00 e2 fc 68 90 01 04 6a 00 68 e8 01 00 00 89 65 10 81 c4 e8 01 00 00 e9 90 01 02 00 00 90 00 } //2
		$a_02_1 = {0f 31 49 29 c2 50 5a 83 f9 02 75 f4 01 cb 02 5d 64 ff d3 e8 90 01 02 ff ff 90 00 } //2
		$a_00_2 = {73 68 65 6c 6c 33 32 } //1 shell32
		$a_00_3 = {73 68 65 6c 6c 33 32 2e 64 6c 6c } //-1 shell32.dll
		$a_00_4 = {6b 65 72 6e 65 6c 33 32 } //1 kernel32
		$a_00_5 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //-1 kernel32.dll
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*-1) >=4
 
}
rule PWS_Win32_Fareit_K_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.K!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {51 00 51 00 50 00 43 00 52 00 65 00 61 00 6c 00 54 00 69 00 6d 00 65 00 53 00 70 00 65 00 65 00 64 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //1 QQPCRealTimeSpeedup.exe
		$a_01_1 = {44 6f 67 6e 61 70 69 6e 67 } //1 Dognaping
		$a_01_2 = {48 61 6c 6c 6f 77 65 6c 6c } //1 Hallowell
		$a_01_3 = {44 72 65 79 66 75 73 73 37 } //1 Dreyfuss7
		$a_01_4 = {50 72 65 63 75 6e 65 75 73 36 } //1 Precuneus6
		$a_01_5 = {48 6f 6b 65 79 70 6f 6b 65 79 34 } //1 Hokeypokey4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}