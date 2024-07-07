
rule Trojan_Win64_CoinMiner_RDC_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 c8 41 39 cb 7e 90 01 01 99 41 f7 f9 48 63 d2 41 8a 04 12 41 30 04 08 48 ff c1 90 00 } //2
		$a_01_1 = {72 65 71 75 65 73 74 65 64 45 78 65 63 75 74 69 6f 6e 4c 65 76 65 6c 20 6c 65 76 65 6c 3d 22 72 65 71 75 69 72 65 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 22 } //1 requestedExecutionLevel level="requireAdministrator"
		$a_01_2 = {72 65 71 75 65 73 74 65 64 50 72 69 76 69 6c 65 67 65 73 } //1 requestedPrivileges
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}