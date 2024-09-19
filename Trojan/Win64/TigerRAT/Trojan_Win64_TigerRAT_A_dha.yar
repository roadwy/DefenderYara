
rule Trojan_Win64_TigerRAT_A_dha{
	meta:
		description = "Trojan:Win64/TigerRAT.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 64 75 6c 65 53 68 65 6c 6c 40 40 } //100 ModuleShell@@
		$a_01_1 = {4d 6f 64 75 6c 65 53 6f 63 6b 73 54 75 6e 6e 65 6c 40 40 } //100 ModuleSocksTunnel@@
		$a_01_2 = {50 72 6f 74 6f 63 6f 6c 54 63 70 50 75 72 65 40 40 } //100 ProtocolTcpPure@@
		$a_01_3 = {50 72 6f 74 6f 63 6f 6c 49 6e 74 65 72 66 61 63 65 40 40 } //100 ProtocolInterface@@
		$a_01_4 = {43 72 79 70 74 6f 72 49 6e 74 65 72 66 61 63 65 40 40 } //100 CryptorInterface@@
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100) >=500
 
}