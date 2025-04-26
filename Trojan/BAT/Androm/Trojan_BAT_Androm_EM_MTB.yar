
rule Trojan_BAT_Androm_EM_MTB{
	meta:
		description = "Trojan:BAT/Androm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {46 55 43 4b 4d 41 43 53 } //1 FUCKMACS
		$a_81_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_2 = {45 6e 73 75 72 65 53 75 63 63 65 73 73 53 74 61 74 75 73 43 6f 64 65 } //1 EnsureSuccessStatusCode
		$a_81_3 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 ConfusedByAttribute
		$a_81_4 = {67 65 74 5f 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 54 79 70 65 } //1 get_NetworkInterfaceType
		$a_81_5 = {30 62 66 35 38 32 65 62 2d 64 66 33 66 2d 34 36 62 61 2d 39 37 61 36 2d 38 64 38 63 61 61 66 34 31 31 33 64 } //1 0bf582eb-df3f-46ba-97a6-8d8caaf4113d
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}