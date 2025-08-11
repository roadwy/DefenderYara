
rule VirTool_Win64_Chisel_G{
	meta:
		description = "VirTool:Win64/Chisel.G,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 70 69 6c 6c 6f 72 61 2f 63 68 69 73 65 6c } //5 jpillora/chisel
		$a_01_1 = {43 48 49 53 45 4c 5f 4b 45 59 } //5 CHISEL_KEY
		$a_01_2 = {63 68 69 73 65 6c 2e 70 69 64 } //5 chisel.pid
		$a_01_3 = {63 6c 69 65 6e 74 2e 66 75 6e 63 31 } //1 client.func1
		$a_01_4 = {2e 47 65 6e 65 72 61 74 65 4b 65 79 } //1 .GenerateKey
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=16
 
}