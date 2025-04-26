
rule Trojan_BAT_Racealer_DF_MTB{
	meta:
		description = "Trojan:BAT/Racealer.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 65 64 2e 65 78 65 } //1 Crypted.exe
		$a_81_1 = {43 6f 6e 66 75 73 65 72 45 78 } //1 ConfuserEx
		$a_81_2 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {67 65 74 5f 49 73 41 6c 69 76 65 } //1 get_IsAlive
		$a_81_5 = {47 65 74 48 49 4e 53 54 41 4e 43 45 } //1 GetHINSTANCE
		$a_81_6 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_7 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_81_8 = {73 65 74 5f 49 73 42 61 63 6b 67 72 6f 75 6e 64 } //1 set_IsBackground
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_11 = {44 65 62 75 67 67 65 72 } //1 Debugger
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}