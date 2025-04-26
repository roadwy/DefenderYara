
rule HackTool_MacOS_Chisel_A_MTB{
	meta:
		description = "HackTool:MacOS/Chisel.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 6a 70 69 6c 6c 6f 72 61 2f 63 68 69 73 65 6c 2f } //1 /jpillora/chisel/
		$a_01_1 = {63 68 69 73 65 6c 63 6c 69 65 6e 74 63 6c 6f 73 65 64 63 6f 6e 66 69 67 63 6f 6f 6b 69 65 } //1 chiselclientclosedconfigcookie
		$a_01_2 = {6d 61 69 6e 2e 67 65 6e 65 72 61 74 65 50 69 64 46 69 6c 65 } //1 main.generatePidFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}