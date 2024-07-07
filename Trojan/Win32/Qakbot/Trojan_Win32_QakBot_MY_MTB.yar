
rule Trojan_Win32_QakBot_MY_MTB{
	meta:
		description = "Trojan:Win32/QakBot.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 08 5f 5d c3 90 0a 45 00 b9 29 00 00 00 b9 29 00 00 00 b9 29 00 00 00 90 02 20 8b 15 90 02 04 33 05 90 02 04 8b d0 89 15 90 02 04 a1 90 02 04 8b 0d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}