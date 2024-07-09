
rule Trojan_Win32_GuLoader_RPB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 34 39 d9 [0-10] 90 13 [0-10] 01 34 3a [0-10] 90 13 [0-10] 81 34 3a [0-10] 90 13 [0-10] 83 ef [0-10] 90 13 [0-10] 83 c7 [0-10] 90 13 [0-10] 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}