
rule Trojan_Win32_Formbook_VC_MTB{
	meta:
		description = "Trojan:Win32/Formbook.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 06 8b 45 90 01 01 8a 04 01 30 02 83 f9 90 01 01 90 13 41 30 1a 8b 45 90 01 01 46 3b f7 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}