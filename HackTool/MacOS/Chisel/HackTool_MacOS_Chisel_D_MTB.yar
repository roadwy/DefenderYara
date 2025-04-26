
rule HackTool_MacOS_Chisel_D_MTB{
	meta:
		description = "HackTool:MacOS/Chisel.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 67 65 6e 65 72 61 74 65 50 69 64 46 69 6c 65 } //1 main.generatePidFile
		$a_01_1 = {63 68 69 73 65 6c 2f 73 65 72 76 65 72 2e 4e 65 77 53 65 72 76 65 72 } //1 chisel/server.NewServer
		$a_01_2 = {2f 63 68 69 73 65 6c 2f 63 6c 69 65 6e 74 } //1 /chisel/client
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}