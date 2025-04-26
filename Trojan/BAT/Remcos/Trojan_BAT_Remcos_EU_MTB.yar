
rule Trojan_BAT_Remcos_EU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 09 00 00 "
		
	strings :
		$a_81_0 = {6d 6f 6e 65 79 2e 53 74 72 61 74 65 67 69 65 73 } //20 money.Strategies
		$a_81_1 = {6d 6f 6e 65 79 2e 65 78 65 } //20 money.exe
		$a_03_2 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-03] 2e 65 78 65 } //20
		$a_03_3 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-03] 2e 44 65 66 69 6e 69 74 69 6f 6e 73 } //20
		$a_03_4 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-03] 2e 41 74 74 72 69 62 75 74 65 73 } //20
		$a_81_5 = {53 61 6e 64 62 6f 78 69 65 20 48 6f 6c 64 69 6e 67 73 2c 20 4c 4c 43 } //1 Sandboxie Holdings, LLC
		$a_81_6 = {53 61 6e 64 62 6f 78 69 65 20 4c 69 63 65 6e 73 65 20 4d 61 6e 61 67 65 72 } //1 Sandboxie License Manager
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_03_2  & 1)*20+(#a_03_3  & 1)*20+(#a_03_4  & 1)*20+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=44
 
}