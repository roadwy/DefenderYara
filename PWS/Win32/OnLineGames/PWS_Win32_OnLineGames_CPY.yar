
rule PWS_Win32_OnLineGames_CPY{
	meta:
		description = "PWS:Win32/OnLineGames.CPY,SIGNATURE_TYPE_PEHSTR,25 00 25 00 08 00 00 "
		
	strings :
		$a_01_0 = {00 4a 75 6d 70 4f 6e } //10
		$a_01_1 = {00 4a 75 6d 70 4f 66 66 } //10 䨀浵佰晦
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_01_3 = {48 4d 5f 54 43 4c 44 41 4f 4a 49 41 4e 53 4a 5f 49 4e 46 4f } //2 HM_TCLDAOJIANSJ_INFO
		$a_01_4 = {48 4d 5f 4d 45 53 53 41 47 45 44 41 4f 4a 49 41 4e 44 4c 4c } //2 HM_MESSAGEDAOJIANDLL
		$a_01_5 = {48 4d 5f 4d 45 53 53 44 41 4f 4a 49 41 4e 44 4c 4c } //2 HM_MESSDAOJIANDLL
		$a_01_6 = {6d 73 68 6d 64 6a 33 32 2e 64 6c 6c } //1 mshmdj32.dll
		$a_01_7 = {61 76 64 61 6f 6a 69 61 6e 33 32 2e 64 6c 6c } //1 avdaojian32.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=37
 
}