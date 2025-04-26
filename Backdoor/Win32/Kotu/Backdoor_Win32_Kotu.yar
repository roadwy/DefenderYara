
rule Backdoor_Win32_Kotu{
	meta:
		description = "Backdoor:Win32/Kotu,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {be 22 00 00 00 f7 f6 0f be 92 ?? ?? ?? ?? 33 ca 8b 85 d0 fc ff ff 88 8c 05 e0 fd ff ff eb af } //3
		$a_01_1 = {68 64 66 6b 6a 67 68 66 64 73 67 73 75 65 72 79 69 00 } //1 摨武杪晨獤獧敵祲i
		$a_01_2 = {71 71 61 00 25 75 00 } //1
		$a_03_3 = {52 61 73 44 69 61 6c 45 76 65 6e 74 [0-07] 4e 65 77 [0-07] 6d 6f 64 65 6d [0-10] 63 61 62 6c 65 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}
rule Backdoor_Win32_Kotu_2{
	meta:
		description = "Backdoor:Win32/Kotu,SIGNATURE_TYPE_PEHSTR,ffffff9f 00 ffffff9f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {4b 4f 54 55 44 49 41 4c 45 52 5f 49 4e 53 54 41 4e 43 45 } //100 KOTUDIALER_INSTANCE
		$a_01_1 = {52 61 73 47 65 74 45 6e 74 72 79 44 69 61 6c 50 61 72 61 6d 73 41 } //1 RasGetEntryDialParamsA
		$a_01_2 = {52 61 73 53 65 74 45 6e 74 72 79 44 69 61 6c 50 61 72 61 6d 73 41 } //1 RasSetEntryDialParamsA
		$a_01_3 = {52 61 73 53 65 74 45 6e 74 72 79 50 72 6f 70 65 72 74 69 65 73 41 } //1 RasSetEntryPropertiesA
		$a_01_4 = {52 61 73 48 61 6e 67 55 70 41 } //1 RasHangUpA
		$a_01_5 = {52 61 73 47 65 74 43 6f 6e 6e 65 63 74 53 74 61 74 75 73 41 } //1 RasGetConnectStatusA
		$a_01_6 = {52 61 73 45 6e 75 6d 44 65 76 69 63 65 73 41 } //1 RasEnumDevicesA
		$a_01_7 = {52 61 73 47 65 74 45 6e 74 72 79 50 72 6f 70 65 72 74 69 65 73 41 } //1 RasGetEntryPropertiesA
		$a_01_8 = {52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 41 } //1 RasEnumConnectionsA
		$a_01_9 = {52 61 73 44 69 61 6c 41 } //1 RasDialA
		$a_01_10 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //50 ShellExecuteA
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*50) >=159
 
}