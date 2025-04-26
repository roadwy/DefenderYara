
rule Trojan_Win32_QakBot_MZ_MTB{
	meta:
		description = "Trojan:Win32/QakBot.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 08 8b e5 5d c3 90 09 23 00 8b [0-05] 33 ?? c7 [0-09] 01 [0-05] a1 [0-04] 8b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}