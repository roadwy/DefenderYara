
rule Trojan_Win32_Stealc_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 0c 6a 00 6a 00 6a 00 6a 00 ff d6 ff d7 4b 75 e8 b9 73 00 00 00 ba 6d 00 00 00 66 89 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Stealc_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Stealc.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f8 8b 4d f8 8b 51 04 33 55 ec 89 55 d0 8b 45 f8 8b 08 33 4d ec 89 4d 9c 8b 55 bc 03 55 9c 89 55 f0 8d 45 ac } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}