
rule Trojan_Win32_QakBot_MX_MTB{
	meta:
		description = "Trojan:Win32/QakBot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 08 5f 5d c3 90 0a 28 00 8b [0-05] 33 [0-05] 8b ?? 89 15 [0-04] a1 [0-04] 8b 0d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}