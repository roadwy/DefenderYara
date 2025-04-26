
rule Trojan_BAT_DarkTortilla_RPZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,62 00 62 00 1c 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 5f 50 49 44 } //1 set_PID
		$a_01_1 = {73 65 74 5f 41 6e 74 69 56 4d } //10 set_AntiVM
		$a_01_2 = {73 65 74 5f 49 6e 6a 65 63 74 69 6f 6e 50 65 72 73 69 73 74 65 6e 63 65 } //10 set_InjectionPersistence
		$a_01_3 = {73 65 74 5f 53 74 61 72 74 75 70 50 65 72 73 69 73 74 65 6e 63 65 } //1 set_StartupPersistence
		$a_01_4 = {73 65 74 5f 41 6e 74 69 53 61 6e 64 42 6f 78 69 65 } //10 set_AntiSandBoxie
		$a_01_5 = {73 65 74 5f 46 61 6b 65 4d 65 73 73 61 67 65 54 69 74 6c 65 } //10 set_FakeMessageTitle
		$a_01_6 = {73 65 74 5f 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 46 69 6c 65 4e 61 6d 65 } //1 set_InstallationFileName
		$a_01_7 = {73 65 74 5f 57 61 74 63 68 44 6f 67 4e 61 6d 65 } //1 set_WatchDogName
		$a_01_8 = {73 65 74 5f 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 4b 65 79 4e 61 6d 65 } //1 set_InstallationKeyName
		$a_01_9 = {73 65 74 5f 4b 65 65 70 41 6c 69 76 65 } //1 set_KeepAlive
		$a_01_10 = {73 65 74 5f 48 69 64 64 65 6e 53 74 61 72 74 75 70 52 65 67 } //10 set_HiddenStartupReg
		$a_01_11 = {73 65 74 5f 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 52 65 67 69 73 74 65 72 79 50 61 74 68 } //1 set_InstallationRegisteryPath
		$a_01_12 = {61 64 64 5f 43 6c 69 63 6b } //1 add_Click
		$a_01_13 = {50 65 72 66 6f 72 6d 43 6c 69 63 6b } //1 PerformClick
		$a_01_14 = {73 65 74 5f 49 6e 73 74 61 6c 6c 46 6f 6c 64 65 72 } //1 set_InstallFolder
		$a_01_15 = {73 65 74 5f 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 46 6f 6c 64 65 72 } //1 set_InstallationFolder
		$a_01_16 = {73 65 74 5f 54 65 6d 70 46 6f 6c 64 65 72 } //1 set_TempFolder
		$a_01_17 = {73 65 74 5f 53 74 61 72 74 75 70 46 6f 6c 64 65 72 } //1 set_StartupFolder
		$a_01_18 = {43 6c 61 73 73 35 5f 44 65 63 72 79 70 74 65 72 } //1 Class5_Decrypter
		$a_01_19 = {43 6c 61 73 73 38 5f 41 6e 74 69 56 4d 73 } //10 Class8_AntiVMs
		$a_01_20 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //1 set_CreateNoWindow
		$a_01_21 = {73 65 74 5f 46 61 6b 65 4d 65 73 73 61 67 65 53 68 6f 77 } //1 set_FakeMessageShow
		$a_01_22 = {73 65 74 5f 46 61 6b 65 4d 65 73 73 61 67 65 49 63 6f 6e 49 6e 64 65 78 } //1 set_FakeMessageIconIndex
		$a_01_23 = {73 65 74 5f 49 6e 6a 65 63 74 69 6f 6e 48 6f 73 74 49 6e 64 65 78 } //10 set_InjectionHostIndex
		$a_01_24 = {73 65 74 5f 46 61 6b 65 4d 65 73 73 61 67 65 42 6f 64 79 } //1 set_FakeMessageBody
		$a_01_25 = {73 65 74 5f 48 69 64 64 65 6e 53 74 61 72 74 75 70 4b 65 79 } //10 set_HiddenStartupKey
		$a_01_26 = {25 49 6e 6a 65 63 74 69 6f 6e 50 65 72 73 69 73 74 25 } //1 %InjectionPersist%
		$a_01_27 = {25 53 74 61 72 74 75 70 50 65 72 73 69 73 74 25 } //1 %StartupPersist%
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*10+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*10+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*10+(#a_01_24  & 1)*1+(#a_01_25  & 1)*10+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1) >=98
 
}