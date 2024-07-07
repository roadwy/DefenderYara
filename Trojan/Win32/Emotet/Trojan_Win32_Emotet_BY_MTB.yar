
rule Trojan_Win32_Emotet_BY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a c8 f6 d1 f6 d2 0a ca 0a 44 24 90 01 01 22 c8 8b 44 24 90 01 01 88 08 40 89 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BY_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 6a 22 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 0c 8a 04 50 30 01 46 3b 74 24 14 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}