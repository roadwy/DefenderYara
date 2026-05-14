
rule Backdoor_BAT_Caminho_AR_AMTB{
	meta:
		description = "Backdoor:BAT/Caminho.AR!AMTB,SIGNATURE_TYPE_PEHSTR,13 00 13 00 0a 00 00 "
		
	strings :
		$a_01_0 = {63 61 6d 69 6e 68 6f 76 62 73 } //10 caminhovbs
		$a_01_1 = {4c 6f 67 6f 6e 54 72 69 67 67 65 72 } //1 LogonTrigger
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 2e 57 69 6e 33 32 2e 54 61 73 6b 53 63 68 65 64 75 6c 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Microsoft.Win32.TaskScheduler.Properties
		$a_01_3 = {4c 61 7a 79 4c 69 73 74 } //1 LazyList
		$a_01_4 = {44 75 6d 6d 79 4c 6f 67 67 65 72 } //1 DummyLogger
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_6 = {43 61 70 74 75 72 65 } //1 Capture
		$a_01_7 = {73 65 74 5f 55 73 65 72 41 63 63 6f 75 6e 74 44 6f 6d 61 69 6e } //1 set_UserAccountDomain
		$a_01_8 = {73 65 74 5f 55 73 65 72 50 61 73 73 77 6f 72 64 } //1 set_UserPassword
		$a_01_9 = {63 61 6d 69 6e 68 6f } //1 caminho
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=19
 
}