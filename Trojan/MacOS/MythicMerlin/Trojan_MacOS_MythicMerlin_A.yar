
rule Trojan_MacOS_MythicMerlin_A{
	meta:
		description = "Trojan:MacOS/MythicMerlin.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 0e 00 00 02 00 "
		
	strings :
		$a_00_0 = {4e 65 30 6e 64 30 67 2f 6d 65 72 6c 69 6e 2d 61 67 65 6e 74 2f 63 6c 69 65 6e 74 73 2f 6d 79 74 68 69 63 } //01 00  Ne0nd0g/merlin-agent/clients/mythic
		$a_00_1 = {4d 79 74 68 69 63 2f 61 67 65 6e 74 2f 6d 61 69 6e 2e 67 6f } //01 00  Mythic/agent/main.go
		$a_00_2 = {6d 79 74 68 69 63 2e 50 6f 73 74 52 65 73 70 6f 6e 73 65 } //01 00  mythic.PostResponse
		$a_00_3 = {6d 79 74 68 69 63 2e 54 61 73 6b } //01 00  mythic.Task
		$a_00_4 = {6d 79 74 68 69 63 2e 43 6c 69 65 6e 74 } //01 00  mythic.Client
		$a_00_5 = {6d 79 74 68 69 63 2e 43 6f 6e 66 69 67 } //01 00  mythic.Config
		$a_00_6 = {6d 79 74 68 69 63 2e 43 68 65 63 6b 49 6e } //01 00  mythic.CheckIn
		$a_00_7 = {6d 79 74 68 69 63 2e 52 53 41 52 65 71 75 65 73 74 } //01 00  mythic.RSARequest
		$a_00_8 = {6d 79 74 68 69 63 2e 52 53 41 52 65 73 70 6f 6e 73 65 } //01 00  mythic.RSAResponse
		$a_00_9 = {6d 79 74 68 69 63 2e 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 } //01 00  mythic.FileDownload
		$a_00_10 = {6a 6f 62 73 2e 53 68 65 6c 6c 63 6f 64 65 } //01 00  jobs.Shellcode
		$a_00_11 = {6a 6f 62 73 2e 46 69 6c 65 54 72 61 6e 73 66 65 72 } //01 00  jobs.FileTransfer
		$a_01_12 = {4d 65 72 6c 69 6e 43 6c 69 65 6e 74 } //01 00  MerlinClient
		$a_01_13 = {4d 79 74 68 69 63 49 44 } //00 00  MythicID
	condition:
		any of ($a_*)
 
}