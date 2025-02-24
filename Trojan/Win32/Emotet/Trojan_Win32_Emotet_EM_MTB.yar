
rule Trojan_Win32_Emotet_EM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 06 8d 76 04 33 44 24 14 42 89 44 37 fc 3b d3 72 ee } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}