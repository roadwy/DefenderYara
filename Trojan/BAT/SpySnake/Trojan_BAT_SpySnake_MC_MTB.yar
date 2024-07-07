
rule Trojan_BAT_SpySnake_MC_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 09 17 59 11 04 a2 00 09 17 58 0d 09 03 6f 90 01 03 06 fe 02 16 fe 01 13 06 11 06 3a 51 ff ff ff 90 00 } //10
		$a_01_1 = {46 61 72 30 65 72 } //1 Far0er
		$a_01_2 = {53 63 6f 32 65 } //1 Sco2e
		$a_01_3 = {50 61 30 6b 61 67 65 } //1 Pa0kage
		$a_01_4 = {43 6f 6d 70 6c 61 34 6e 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Compla4n.Properties
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}
rule Trojan_BAT_SpySnake_MC_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 06 11 08 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 08 17 58 13 08 20 90 01 03 9e 38 90 01 03 ff 90 00 } //10
		$a_01_1 = {50 72 69 73 6f 6e 65 72 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 5f 2e 50 72 6f 70 65 72 74 69 65 73 } //2 PrisonerManagementSystem_.Properties
		$a_01_2 = {65 6d 70 6c 6f 79 65 65 43 6f 6e 74 72 6f 6c 31 5f 4c 6f 61 64 } //2 employeeControl1_Load
		$a_01_3 = {70 72 69 73 6f 6e 65 72 43 6f 6e 74 72 6f 6c 31 5f 4c 6f 61 64 } //2 prisonerControl1_Load
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}
rule Trojan_BAT_SpySnake_MC_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 4b 6f 6e 73 6f 6c 65 } //1 GetKonsole
		$a_81_1 = {45 6e 63 6f 64 65 72 } //1 Encoder
		$a_81_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_3 = {78 6d 34 57 34 62 4a 51 61 54 } //1 xm4W4bJQaT
		$a_81_4 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_5 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_81_6 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_8 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}