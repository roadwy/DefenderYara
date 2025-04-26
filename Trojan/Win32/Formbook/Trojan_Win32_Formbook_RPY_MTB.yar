
rule Trojan_Win32_Formbook_RPY_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 45 ff 83 f0 53 88 45 ff 0f b6 45 ff 2b 45 f8 88 45 ff 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 88 45 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Formbook_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 45 f8 88 45 ff 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 88 45 ff 0f b6 45 ff 83 f0 1f 88 45 ff 8b 45 f0 03 45 f8 8a 4d ff 88 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}