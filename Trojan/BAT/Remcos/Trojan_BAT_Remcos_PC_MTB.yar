
rule Trojan_BAT_Remcos_PC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {71 77 65 72 74 79 75 69 6f 70 61 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d } //1 qwertyuiopasdfghjklzxcvbnm
		$a_81_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_3 = {7a 43 6f 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 zCom.resources
		$a_81_4 = {4b 6f 6c 69 6b 6f 78 } //1 Kolikox
		$a_81_5 = {47 65 74 49 6e 73 74 61 6e 63 65 } //1 GetInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_7 = {2e 74 6d 70 2e 65 78 65 } //1 .tmp.exe
		$a_81_8 = {31 32 33 34 35 36 37 38 39 30 } //1 1234567890
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}