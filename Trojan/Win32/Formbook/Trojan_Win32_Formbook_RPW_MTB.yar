
rule Trojan_Win32_Formbook_RPW_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 b8 89 45 a8 8b 45 cc b9 0c 00 00 00 99 f7 f9 8b 45 a8 0f b6 34 10 8b 45 d0 8b 4d cc 0f b6 14 08 31 f2 88 14 08 8b 45 cc 83 c0 01 89 45 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}