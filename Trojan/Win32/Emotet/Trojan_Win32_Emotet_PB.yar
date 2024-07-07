
rule Trojan_Win32_Emotet_PB{
	meta:
		description = "Trojan:Win32/Emotet.PB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ff c7 05 90 01 04 00 00 00 00 8b ff 01 05 90 01 04 8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}