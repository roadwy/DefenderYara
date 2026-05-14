
rule Trojan_Win64_TransferLoader_ATL_MTB{
	meta:
		description = "Trojan:Win64/TransferLoader.ATL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 48 c6 44 24 28 eb c6 44 24 29 08 c6 44 24 2a 48 c6 44 24 2b 89 c6 44 24 2c 8c c6 44 24 2d 24 c6 44 24 2e d8 c6 44 24 2f de c6 44 24 30 ec c6 44 24 31 03 c6 44 24 32 c3 48 8d 44 24 48 48 85 c0 75 0b 48 8d 44 24 28 ff d0 33 c0 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}