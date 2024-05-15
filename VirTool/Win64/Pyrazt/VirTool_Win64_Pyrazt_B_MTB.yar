
rule VirTool_Win64_Pyrazt_B_MTB{
	meta:
		description = "VirTool:Win64/Pyrazt.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 6f 6e 74 72 6f 6c 6c 65 72 73 2f 65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 2e 67 6f } //01 00  controllers/executeCommand.go
		$a_81_1 = {73 72 63 2f 63 6f 6e 74 72 6f 6c 6c 65 72 73 2e 55 70 6c 6f 61 64 43 6f 6d 6d 61 6e 64 } //01 00  src/controllers.UploadCommand
		$a_81_2 = {70 61 69 72 61 74 2f 73 72 63 2f 73 65 72 76 65 72 2e 67 6f } //01 00  pairat/src/server.go
		$a_81_3 = {70 61 69 72 61 74 2f 73 72 63 2f 74 6f 6f 6c 73 2f 6b 69 6c 6c 50 72 6f 63 63 65 73 73 2e 67 6f } //01 00  pairat/src/tools/killProccess.go
		$a_81_4 = {70 61 69 72 61 74 2f 73 72 63 2f 74 6f 6f 6c 73 2f 65 78 65 63 75 74 65 4e 67 72 6f 6b 2e 67 6f } //01 00  pairat/src/tools/executeNgrok.go
		$a_81_5 = {6e 65 74 2f 68 74 74 70 2e 70 65 72 73 69 73 74 43 6f 6e 6e 57 72 69 74 65 72 2e 57 72 69 74 65 } //01 00  net/http.persistConnWriter.Write
		$a_81_6 = {2e 73 6f 63 6b 73 41 75 74 68 4d 65 74 68 6f 64 } //00 00  .socksAuthMethod
	condition:
		any of ($a_*)
 
}