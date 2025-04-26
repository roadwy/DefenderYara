
rule Trojan_BAT_NjRat_NEQ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0a 00 00 "
		
	strings :
		$a_01_0 = {43 43 48 45 4b 4c 4a 42 4c 44 42 4d 4e } //5 CCHEKLJBLDBMN
		$a_01_1 = {47 4d 49 4f 46 4c 49 45 4b 50 45 4b 45 } //5 GMIOFLIEKPEKE
		$a_01_2 = {53 46 55 34 6d 62 54 33 47 4d 72 65 } //5 SFU4mbT3GMre
		$a_01_3 = {66 69 65 6c 64 69 6d 70 6c 33 } //4 fieldimpl3
		$a_01_4 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //4 get_MachineName
		$a_01_5 = {53 68 65 6c 6c } //1 Shell
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_7 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 NtSetInformationProcess
		$a_01_8 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 } //1 GetProcessesByName
		$a_01_9 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=28
 
}