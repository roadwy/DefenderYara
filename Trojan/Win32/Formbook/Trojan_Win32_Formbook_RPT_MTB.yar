
rule Trojan_Win32_Formbook_RPT_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 0f ef c5 66 0f fc c6 66 0f ef c7 66 0f fc c2 66 0f ef c3 f3 0f 7f 01 83 c1 20 83 c2 e0 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}