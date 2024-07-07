
rule Trojan_BAT_AgentTesla_JRD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {34 39 65 66 31 66 32 65 2d 39 35 33 37 2d 34 37 30 63 2d 62 38 36 39 2d 39 62 64 64 35 32 30 31 30 66 34 32 } //1 49ef1f2e-9537-470c-b869-9bdd52010f42
		$a_81_1 = {41 63 63 6f 75 6e 74 4d 61 6e 61 67 65 } //1 AccountManage
		$a_81_2 = {70 65 6f 70 6c 65 2e 78 6d 6c } //1 people.xml
		$a_81_3 = {70 65 6f 70 6c 65 2e 63 73 76 } //1 people.csv
		$a_81_4 = {30 53 38 68 65 7a 65 47 4b 31 77 } //1 0S8hezeGK1w
		$a_81_5 = {4b 4b 38 34 73 79 51 7a 69 33 70 47 70 4d 54 6b 6e 30 } //1 KK84syQzi3pGpMTkn0
		$a_81_6 = {34 7a 65 63 68 4c 45 78 4a 69 45 4b 78 71 53 58 } //1 4zechLExJiEKxqSX
		$a_81_7 = {56 6a 4d 33 6e 49 53 78 4d 53 59 68 43 7a 65 } //1 VjM3nISxMSYhCze
		$a_81_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_10 = {53 79 73 74 65 6d 2e 41 63 74 69 76 61 74 6f 72 } //1 System.Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}