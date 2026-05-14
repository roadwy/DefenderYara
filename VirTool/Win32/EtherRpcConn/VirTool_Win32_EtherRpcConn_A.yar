
rule VirTool_Win32_EtherRpcConn_A{
	meta:
		description = "VirTool:Win32/EtherRpcConn.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {2c 22 6d 65 74 68 6f 64 22 3a 22 65 74 68 5f 63 61 6c 6c 22 2c 22 70 61 72 61 6d 73 22 3a } //5 ,"method":"eth_call","params":
		$a_03_1 = {62 63 31 71 [0-10] 62 63 31 70 } //1
		$a_03_2 = {62 69 74 63 6f 69 6e 63 61 73 68 3a 71 [0-10] 62 69 74 63 6f 69 6e 63 61 73 68 3a 70 } //1
		$a_01_3 = {6c 74 63 31 71 00 } //1 瑬ㅣq
		$a_01_4 = {63 6f 73 6d 6f 73 31 00 } //1 潣浳獯1
		$a_01_5 = {2e 62 69 6e 61 6e 63 65 2e 6f 72 67 } //1 .binance.org
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}