
rule Trojan_Win64_Staser_SX_MTB{
	meta:
		description = "Trojan:Win64/Staser.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 ff ca 48 89 54 24 ?? 48 f7 da 48 c1 fa 3f 83 e2 10 48 8b 74 24 ?? 48 01 f2 48 89 54 24 } //30
		$a_01_1 = {58 30 20 2a 6d 61 69 6e 2e 49 50 43 53 65 72 76 65 72 } //10 X0 *main.IPCServer
		$a_01_2 = {58 31 20 2a 6d 61 69 6e 2e 43 6f 6e 66 69 67 } //10 X1 *main.Config
		$a_01_3 = {6a 73 6f 6e 3a 22 64 69 73 63 6f 76 65 72 79 5f 64 6f 6d 61 69 6e } //5 json:"discovery_domain
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5) >=55
 
}