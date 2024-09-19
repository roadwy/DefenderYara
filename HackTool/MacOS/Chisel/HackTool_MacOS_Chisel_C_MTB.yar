
rule HackTool_MacOS_Chisel_C_MTB{
	meta:
		description = "HackTool:MacOS/Chisel.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 6a 70 69 6c 6c 6f 72 61 2f 63 68 69 73 65 6c 2f 73 68 61 72 65 2f 63 63 72 79 70 74 6f 2e 49 73 43 68 69 73 65 6c 4b 65 79 } //2 /jpillora/chisel/share/ccrypto.IsChiselKey
		$a_01_1 = {63 68 69 73 65 6c 2f 63 6c 69 65 6e 74 } //1 chisel/client
		$a_01_2 = {43 48 49 53 45 4c 5f 4b 45 59 5f 46 49 4c 45 } //1 CHISEL_KEY_FILE
		$a_01_3 = {6d 61 69 6e 2e 67 65 6e 65 72 61 74 65 50 69 64 46 69 6c 65 } //1 main.generatePidFile
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}