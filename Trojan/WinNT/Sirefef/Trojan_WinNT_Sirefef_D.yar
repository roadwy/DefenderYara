
rule Trojan_WinNT_Sirefef_D{
	meta:
		description = "Trojan:WinNT/Sirefef.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7c 1c 6a 62 68 90 01 04 6a 01 6a 00 68 90 01 04 ff 74 24 20 ff d6 ff 74 24 0c ff d7 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_WinNT_Sirefef_D_2{
	meta:
		description = "Trojan:WinNT/Sirefef.D,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7c 1c 6a 62 68 90 01 04 6a 01 6a 00 68 90 01 04 ff 74 24 20 ff d6 ff 74 24 0c ff d7 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}