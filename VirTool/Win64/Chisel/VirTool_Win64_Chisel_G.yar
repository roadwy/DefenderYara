
rule VirTool_Win64_Chisel_G{
	meta:
		description = "VirTool:Win64/Chisel.G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 67 65 6e 65 72 61 74 65 50 69 64 46 69 6c 65 } //1 .generatePidFile
		$a_01_1 = {43 48 49 53 45 4c 5f 4b 45 59 } //1 CHISEL_KEY
		$a_01_2 = {63 68 69 73 65 6c 2e 70 69 64 } //1 chisel.pid
		$a_01_3 = {63 6c 69 65 6e 74 2e 66 75 6e 63 31 } //1 client.func1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}