
rule Trojan_BAT_AgentTesla_LVJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {56 00 61 00 67 00 69 00 6e 00 61 00 2e 00 4d 00 61 00 69 00 6e 00 00 0b 53 00 74 00 61 00 72 00 74 } //1
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 4c 50 5c 44 65 73 6b 74 6f 70 5c 6c 6f 61 64 65 72 5c 6c 6f 61 64 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 6c 6f 61 64 65 72 2e 70 64 62 } //1 C:\Users\LP\Desktop\loader\loader\obj\Debug\loader.pdb
		$a_81_2 = {56 61 67 69 6e 61 2e 4d 61 69 6e } //1 Vagina.Main
		$a_01_3 = {6c 6f 61 64 65 72 2e 65 78 65 } //1 loader.exe
		$a_01_4 = {67 5f 5f 47 65 74 4c 69 62 72 61 72 79 } //1 g__GetLibrary
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_8 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_9 = {50 72 6f 67 72 61 6d } //1 Program
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}