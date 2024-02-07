
rule VirTool_Win32_Pyrazt_A_MTB{
	meta:
		description = "VirTool:Win32/Pyrazt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 6f 6e 74 72 6f 6c 6c 65 72 73 2f 65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 2e 67 6f } //01 00  controllers/executeCommand.go
		$a_81_1 = {73 72 63 2f 63 6f 6e 74 72 6f 6c 6c 65 72 73 2e 55 70 6c 6f 61 64 43 6f 6d 6d 61 6e 64 } //01 00  src/controllers.UploadCommand
		$a_81_2 = {70 61 69 72 61 74 2f 70 61 69 72 61 74 2f 73 72 63 2f 73 65 72 76 65 72 2e 67 6f } //00 00  pairat/pairat/src/server.go
	condition:
		any of ($a_*)
 
}