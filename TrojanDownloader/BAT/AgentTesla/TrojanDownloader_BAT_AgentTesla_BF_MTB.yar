
rule TrojanDownloader_BAT_AgentTesla_BF_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 00 30 00 37 00 2e 00 31 00 37 00 32 00 2e 00 31 00 33 00 2e 00 31 00 35 00 34 00 } //5 107.172.13.154
		$a_01_1 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule TrojanDownloader_BAT_AgentTesla_BF_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 00 70 00 61 00 72 00 61 00 74 00 65 00 64 00 65 00 63 00 75 00 72 00 61 00 74 00 61 00 74 00 2e 00 72 00 6f 00 2f 00 4d 00 41 00 4e 00 4e 00 59 00 2f 00 6e 00 65 00 77 00 44 00 44 00 4c 00 4c 00 4c 00 4c 00 4c 00 2e 00 74 00 78 00 74 00 } //1 aparatedecuratat.ro/MANNY/newDDLLLLL.txt
		$a_01_1 = {55 00 45 00 38 00 77 00 4e 00 54 00 4d 00 79 00 4d 00 6a 00 41 00 79 00 4d 00 69 00 55 00 } //1 UE8wNTMyMjAyMiU
		$a_01_2 = {54 00 48 00 45 00 44 00 45 00 56 00 49 00 4c 00 2e 00 44 00 45 00 56 00 49 00 4c 00 44 00 45 00 56 00 49 00 4c 00 } //1 THEDEVIL.DEVILDEVIL
		$a_01_3 = {43 00 68 00 65 00 63 00 6b 00 52 00 65 00 6d 00 6f 00 74 00 65 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 50 00 72 00 65 00 73 00 65 00 6e 00 74 00 } //1 CheckRemoteDebuggerPresent
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}