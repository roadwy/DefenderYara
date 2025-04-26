
rule Backdoor_BAT_Turla_DB_MTB{
	meta:
		description = "Backdoor:BAT/Turla.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {41 67 65 6e 74 2e 65 78 65 } //1 Agent.exe
		$a_81_1 = {53 74 6f 70 77 61 74 63 68 } //1 Stopwatch
		$a_81_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_81_4 = {43 6f 6e 66 75 73 65 72 45 78 20 76 30 2e 36 2e 30 } //1 ConfuserEx v0.6.0
		$a_81_5 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 ConfusedByAttribute
		$a_81_6 = {53 79 73 69 6e 74 65 72 6e 61 6c 73 20 44 65 62 75 67 56 69 65 77 } //1 Sysinternals DebugView
		$a_81_7 = {50 75 62 6c 69 63 4b 65 79 54 6f 6b 65 6e 3d 62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 } //1 PublicKeyToken=b77a5c561934e089
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}