
rule Trojan_Win32_Formbook_VD_MTB{
	meta:
		description = "Trojan:Win32/Formbook.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 80 ?? ?? ?? ?? 34 ?? 8b 55 ?? 03 55 ?? 88 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}