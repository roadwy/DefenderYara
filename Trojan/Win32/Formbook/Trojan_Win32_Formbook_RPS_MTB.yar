
rule Trojan_Win32_Formbook_RPS_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {43 ff 4d 98 90 13 90 90 90 90 90 90 90 90 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}