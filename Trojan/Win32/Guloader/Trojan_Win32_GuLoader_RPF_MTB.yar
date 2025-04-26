
rule Trojan_Win32_GuLoader_RPF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 34 39 dd [0-10] 90 13 [0-10] 01 34 3a [0-10] 90 13 [0-10] 81 34 3a [0-10] 90 13 [0-10] 83 ef [0-10] 90 13 [0-10] 83 c7 [0-10] 90 13 [0-10] 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_GuLoader_RPF_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 34 24 02 5c 4a ba [0-10] 90 13 [0-10] 90 13 [0-10] 90 13 8f 04 30 [0-10] 90 13 [0-10] 90 13 [0-10] 90 13 [0-10] 90 13 83 de 28 [0-10] 90 13 [0-10] 90 13 83 d6 24 [0-10] 90 13 90 13 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}