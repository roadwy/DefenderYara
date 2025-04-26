
rule Trojan_Win32_Formbook_RPF_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 39 04 ?? 34 ?? 04 ?? 88 04 39 41 3b cb 72 ef } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}