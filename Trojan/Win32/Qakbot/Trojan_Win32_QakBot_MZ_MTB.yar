
rule Trojan_Win32_QakBot_MZ_MTB{
	meta:
		description = "Trojan:Win32/QakBot.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 08 8b e5 5d c3 90 09 23 00 8b 90 02 05 33 90 01 01 c7 90 02 09 01 90 02 05 a1 90 02 04 8b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}