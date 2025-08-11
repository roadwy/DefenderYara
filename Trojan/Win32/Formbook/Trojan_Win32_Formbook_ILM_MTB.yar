
rule Trojan_Win32_Formbook_ILM_MTB{
	meta:
		description = "Trojan:Win32/Formbook.ILM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 4c 30 01 80 e9 ?? 30 0c 30 40 3b c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}