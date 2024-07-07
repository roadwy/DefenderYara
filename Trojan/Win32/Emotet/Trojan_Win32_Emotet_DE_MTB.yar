
rule Trojan_Win32_Emotet_DE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 ff 74 27 29 c9 49 23 0a 83 c2 04 83 c1 ee 31 d9 8d 49 ff 89 cb 89 4e 00 83 ef 04 83 ee fc c7 05 90 02 04 07 1a 40 00 eb 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_DE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 f1 83 c6 01 8b ca 8b 54 24 14 8a 44 32 ff 8b d1 2b d3 0f b6 14 3a 88 54 2e ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}