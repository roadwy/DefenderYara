
rule Trojan_Win32_GuLoader_RPE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0b 1c 3a 83 [0-10] 81 f3 [0-10] 09 1c 38 [0-10] 83 ef [0-10] 81 ff [0-10] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}