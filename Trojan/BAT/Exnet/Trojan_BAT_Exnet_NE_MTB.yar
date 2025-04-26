
rule Trojan_BAT_Exnet_NE_MTB{
	meta:
		description = "Trojan:BAT/Exnet.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 66 20 61 64 64 20 63 72 65 64 69 74 20 46 55 4c 4c 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 mf add credit FULL.g.resources
		$a_01_1 = {4d 72 65 52 2e 69 62 2b 63 } //1 MreR.ib+c
		$a_01_2 = {4d 72 65 52 2e 69 62 2b 62 } //1 MreR.ib+b
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_4 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_5 = {6d 66 5f 61 64 64 63 72 65 64 69 74 2e 50 72 6f 70 65 72 74 69 65 73 } //1 mf_addcredit.Properties
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}