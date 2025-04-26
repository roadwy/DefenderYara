
rule Trojan_Win32_Stealc_RPY_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 ca a6 60 31 ca a6 60 31 ca a6 60 31 ca a6 60 31 ca a6 60 31 ca a6 76 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Stealc_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Stealc.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 34 89 7c 24 1c 8b 44 24 34 01 44 24 1c 8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 4c 24 1c 89 4c 24 1c 8b 44 24 1c 29 44 24 14 8b 54 24 14 c1 e2 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}