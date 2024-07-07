
rule Trojan_BAT_AgentTesla_MP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {1c 9a 0c 08 19 8d 90 01 02 00 01 25 16 7e 90 01 02 00 04 a2 25 17 7e 90 01 02 00 04 a2 25 18 72 90 01 02 00 70 a2 28 90 01 02 00 0a 26 1f 17 8c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {48 56 4e 6b 70 6b 5a 33 34 4b 6d 65 63 69 56 56 4a 66 69 } //1 HVNkpkZ34KmeciVVJfi
		$a_01_1 = {63 64 61 57 39 4f 76 4d 55 39 } //1 cdaW9OvMU9
		$a_01_2 = {4f 52 71 46 65 51 4d 41 4d 54 76 38 6d 52 78 76 77 53 72 } //1 ORqFeQMAMTv8mRxvwSr
		$a_01_3 = {75 67 6c 64 71 35 4d 57 57 31 52 6e 31 78 73 44 62 58 71 } //1 ugldq5MWW1Rn1xsDbXq
		$a_01_4 = {79 6b 56 6c 48 48 4d 62 55 67 44 69 73 78 54 37 53 78 53 } //1 ykVlHHMbUgDisxT7SxS
		$a_01_5 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //1 kLjw4iIsCLsZtxc4lksN0j
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_7 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_9 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_10 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}