
rule VirTool_Win32_WierdFunguz_A_MTB{
	meta:
		description = "VirTool:Win32/WierdFunguz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {56 69 6f 6c 65 6e 74 46 75 6e 67 75 73 2d 43 32 2d 6d 61 69 6e 5c 73 72 63 5c 43 6f 6d 6d 61 6e 64 48 61 6e 64 6c 65 72 2e } //1 ViolentFungus-C2-main\src\CommandHandler.
		$a_81_1 = {5c 73 72 63 5c 53 65 72 76 69 63 65 54 63 70 50 72 6f 63 65 73 73 6f 72 2e } //1 \src\ServiceTcpProcessor.
		$a_81_2 = {56 69 6f 6c 65 6e 74 46 75 6e 67 75 73 2d 43 32 2d 6d 61 69 6e 5c 73 72 63 5c 44 61 74 61 52 65 71 75 65 73 74 50 72 6f 63 65 73 73 6f 72 2e } //1 ViolentFungus-C2-main\src\DataRequestProcessor.
		$a_81_3 = {5c 73 72 63 5c 53 65 72 76 69 63 65 54 63 70 2e } //1 \src\ServiceTcp.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}