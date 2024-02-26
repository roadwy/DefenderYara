
rule Trojan_Win64_CryptInject_BMC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 33 0c 20 48 c1 eb 18 41 33 4c 9d 00 41 89 c9 89 c8 44 89 d9 41 89 e8 31 e8 89 c3 44 31 d3 33 5c ba f4 0f b6 f3 41 33 0c b6 0f b6 f7 41 33 0c b7 48 89 de } //01 00 
		$a_01_1 = {64 65 70 73 5c 73 68 65 6c 6c 63 6f 64 65 5f 72 75 6e 6e 65 72 2e 70 64 62 } //00 00  deps\shellcode_runner.pdb
	condition:
		any of ($a_*)
 
}