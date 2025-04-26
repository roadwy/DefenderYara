
rule Trojan_BAT_AgentTesla_DB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_00_0 = {01 57 15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 58 00 00 00 06 00 00 00 5b 00 00 00 e0 } //3
		$a_01_1 = {49 6e 74 65 72 6e 61 6c 44 65 63 6f 64 65 72 42 65 73 74 46 69 74 46 61 6c 6c 62 } //3 InternalDecoderBestFitFallb
		$a_01_2 = {73 65 74 5f 53 68 6f 72 74 63 75 74 4b 65 79 73 } //3 set_ShortcutKeys
		$a_01_3 = {49 45 6e 75 6d 53 54 4f 52 45 43 41 54 45 47 4f 52 59 49 4e 53 54 41 2e 65 78 65 } //3 IEnumSTORECATEGORYINSTA.exe
		$a_01_4 = {73 65 74 5f 48 65 6c 70 4c 69 6e 6b } //3 set_HelpLink
		$a_01_5 = {67 65 74 5f 49 73 43 6f 6d 70 6c 65 74 65 64 } //3 get_IsCompleted
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}
rule Trojan_BAT_AgentTesla_DB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 37 34 63 64 62 65 30 37 2d 61 39 35 62 2d 34 38 31 61 2d 39 64 38 35 2d 35 35 34 36 65 64 36 31 35 34 64 38 } //1 $74cdbe07-a95b-481a-9d85-5546ed6154d8
		$a_81_1 = {52 65 63 6f 72 64 42 67 79 53 79 73 74 65 6d 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 RecordBgySystem.My.Resources
		$a_81_2 = {52 65 63 6f 72 64 42 67 79 53 79 73 74 65 6d 2e 52 65 73 5f 64 65 6c 65 74 65 2e 72 65 73 6f 75 72 63 65 73 } //1 RecordBgySystem.Res_delete.resources
		$a_81_3 = {42 61 72 61 6e 67 61 79 20 52 65 73 6f 6c 75 74 69 6f 6e 73 } //1 Barangay Resolutions
		$a_81_4 = {50 75 72 6f 6b 20 69 73 20 45 6d 70 74 79 } //1 Purok is Empty
		$a_81_5 = {43 68 75 72 63 68 20 6f 66 20 43 68 72 69 73 74 } //1 Church of Christ
		$a_81_6 = {42 69 62 6c 65 20 42 61 70 74 69 73 74 20 43 68 75 72 63 68 } //1 Bible Baptist Church
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}