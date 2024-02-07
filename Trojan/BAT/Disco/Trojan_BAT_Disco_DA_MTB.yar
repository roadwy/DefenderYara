
rule Trojan_BAT_Disco_DA_MTB{
	meta:
		description = "Trojan:BAT/Disco.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 65 6e 65 77 61 62 6c 65 43 68 65 61 74 } //01 00  RenewableCheat
		$a_81_1 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //01 00  //cdn.discordapp.com/attachments/
		$a_81_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_81_5 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_81_6 = {4c 6f 6f 70 41 } //01 00  LoopA
		$a_81_7 = {4c 6f 6f 70 42 } //00 00  LoopB
	condition:
		any of ($a_*)
 
}