
rule Trojan_BAT_AgentTesla_MQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,53 00 53 00 10 00 00 "
		
	strings :
		$a_01_0 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //20 kLjw4iIsCLsZtxc4lksN0j
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //10 DebuggableAttribute
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //10 DownloadFile
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //10 CreateInstance
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //10 MemoryStream
		$a_01_5 = {52 65 76 65 72 73 65 } //10 Reverse
		$a_01_6 = {52 65 70 6c 61 63 65 } //10 Replace
		$a_01_7 = {75 6f 31 6f 75 72 6e 57 41 37 5a 78 34 6b 44 55 70 64 33 } //1 uo1ournWA7Zx4kDUpd3
		$a_01_8 = {55 37 4d 4a 4a 47 70 67 48 45 51 63 57 4d 44 67 34 4e } //1 U7MJJGpgHEQcWMDg4N
		$a_01_9 = {6b 4c 54 4d 6f 46 75 43 6b } //1 kLTMoFuCk
		$a_01_10 = {67 44 6e 4b 78 49 6c 78 65 49 78 4d 36 69 53 71 73 79 61 } //1 gDnKxIlxeIxM6iSqsya
		$a_01_11 = {56 51 32 44 74 49 67 6f 6d 5a 67 4e 45 74 35 4f 46 68 } //1 VQ2DtIgomZgNEt5OFh
		$a_01_12 = {6d 4d 79 70 4e 77 74 59 59 77 77 6e 77 6e 48 6d 49 48 38 } //1 mMypNwtYYwwnwnHmIH8
		$a_01_13 = {69 36 37 53 49 6b 6b 32 6c 4f 47 62 30 54 58 61 6f 6d 48 } //1 i67SIkk2lOGb0TXaomH
		$a_01_14 = {4e 4d 4c 68 6c 49 6b 34 4a 33 72 43 62 54 38 77 39 54 66 } //1 NMLhlIk4J3rCbT8w9Tf
		$a_01_15 = {52 68 57 6c 61 6a 6b 6d 67 75 35 74 6a 38 55 45 49 63 6c } //1 RhWlajkmgu5tj8UEIcl
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=83
 
}