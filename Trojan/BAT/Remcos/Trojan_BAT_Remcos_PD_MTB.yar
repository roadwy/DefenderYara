
rule Trojan_BAT_Remcos_PD_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 09 00 00 "
		
	strings :
		$a_81_0 = {24 37 64 30 64 38 33 34 31 2d 30 31 61 31 2d 34 35 38 63 2d 61 62 32 66 2d 64 62 37 39 38 33 31 39 31 33 63 36 } //10 $7d0d8341-01a1-458c-ab2f-db79831913c6
		$a_81_1 = {24 62 63 33 66 31 37 66 62 2d 33 65 61 61 2d 34 64 34 61 2d 38 66 62 65 2d 35 32 36 31 33 38 30 65 30 34 62 65 } //10 $bc3f17fb-3eaa-4d4a-8fbe-5261380e04be
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {50 72 69 6d 65 58 2e 54 6f 6f 6c 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 PrimeX.Tools.Properties.Resources
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_5 = {73 68 75 74 64 6f 77 6e 74 69 6d 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 shutdowntimer.Properties.Resources
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=15
 
}