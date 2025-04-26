
rule Trojan_Win32_PrivateLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/PrivateLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f5 66 3b ee 89 75 bc 8b f7 f6 c1 a9 d3 e6 8b 4d 0c 66 3b fb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_PrivateLoader_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/PrivateLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 84 24 ?? ?? 00 00 50 ff d6 8d 8c 24 ?? 00 00 00 51 ff d7 6a 00 6a 00 ff d3 8d 94 24 ?? ?? 00 00 52 6a 00 ff d5 83 6c 24 10 01 75 ac } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}