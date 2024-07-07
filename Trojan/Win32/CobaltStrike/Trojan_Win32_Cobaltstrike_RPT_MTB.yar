
rule Trojan_Win32_Cobaltstrike_RPT_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 70 29 c6 c6 00 e9 83 ee 05 89 70 01 8b 44 24 78 8b 74 24 1c 89 30 8b 44 24 30 89 5c 24 0c 89 44 24 08 8b 44 24 70 c7 44 24 04 05 00 00 00 89 04 24 8b 44 24 18 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}