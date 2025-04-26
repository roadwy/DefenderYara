
rule Ransom_MSIL_LokiLocker_ZA_MTB{
	meta:
		description = "Ransom:MSIL/LokiLocker.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_01_1 = {4b 69 6c 6c 53 77 69 74 63 68 } //1 KillSwitch
		$a_01_2 = {4c 6f 6b 69 2e 55 74 69 6c 69 74 69 65 73 2e 49 6e 74 65 72 66 61 63 65 73 } //1 Loki.Utilities.Interfaces
		$a_01_3 = {4c 6f 6b 69 2e 49 4f 2e 4b 65 79 62 6f 61 72 64 73 2e 53 65 74 74 69 6e 67 73 } //1 Loki.IO.Keyboards.Settings
		$a_01_4 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_6 = {44 65 62 75 67 67 65 72 20 44 65 74 65 63 74 65 64 } //1 Debugger Detected
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}