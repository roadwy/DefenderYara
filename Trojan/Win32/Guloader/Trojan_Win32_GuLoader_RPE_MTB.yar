
rule Trojan_Win32_GuLoader_RPE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0b 1c 3a 83 90 02 10 81 f3 90 02 10 09 1c 38 90 02 10 83 ef 90 02 10 81 ff 90 02 10 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}