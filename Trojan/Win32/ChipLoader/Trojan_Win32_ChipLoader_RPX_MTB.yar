
rule Trojan_Win32_ChipLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/ChipLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 89 e2 81 c2 04 00 00 00 83 ea 04 87 14 24 5c 89 04 24 89 34 24 56 89 e6 81 c6 04 00 00 00 83 ee 04 87 34 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}