
rule Trojan_BAT_AgentTesla_NYP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 48 47 44 46 48 4b 44 4c 48 44 4a 44 2e 64 6c 6c } //1 WHGDFHKDLHDJD.dll
		$a_01_1 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64GetThreadContext
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_3 = {55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 UnmapViewOfSection
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_5 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_6 = {63 32 30 36 35 64 38 62 37 63 62 63 } //1 c2065d8b7cbc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_NYP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 31 00 2e 00 78 00 61 00 6d 00 6c 00 00 57 43 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 } //1
		$a_01_1 = {17 b6 0b 09 1f 00 00 00 fa 01 33 00 16 00 00 01 } //1
		$a_01_2 = {30 00 22 00 31 00 23 00 33 00 24 00 36 00 25 00 39 00 26 00 3a 00 29 00 3b } //1
		$a_81_3 = {52 53 35 35 51 37 34 44 37 48 37 47 48 } //1 RS55Q74D7H7GH
		$a_81_4 = {47 65 74 4f 62 6a 65 63 74 } //1 GetObject
		$a_81_5 = {53 79 73 74 65 6d 2e 44 65 73 69 67 6e 2e 44 69 61 67 72 61 6d 2e 51 4d 2e 72 } //1 System.Design.Diagram.QM.r
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}