
rule Trojan_Win32_GuLoader_RPC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c1 00 8b 34 39 [0-10] 90 13 [0-10] 01 34 3a [0-10] 90 13 [0-10] 81 34 3a [0-10] 90 13 [0-10] 83 ef [0-10] 90 13 [0-10] 83 c7 [0-10] 90 13 [0-10] 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_GuLoader_RPC_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 04 13 9b 90 9b 9b d9 ea d9 c9 d9 e4 0f dc ef } //1
		$a_01_1 = {81 fb c8 00 00 00 83 f9 17 01 34 08 83 f9 0c 0f 73 f7 61 0f db f1 } //1
		$a_01_2 = {09 04 31 90 66 0f eb cc eb 3e 9f 91 2d 75 31 31 31 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}