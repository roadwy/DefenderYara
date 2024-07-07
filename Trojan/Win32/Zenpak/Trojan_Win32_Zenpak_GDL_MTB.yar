
rule Trojan_Win32_Zenpak_GDL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 89 c1 d1 e9 ba 93 24 49 92 89 45 ec 89 c8 f7 e2 c1 ea 02 6b c2 0e 8b 4d ec 29 c1 89 c8 83 e8 0a 89 4d e8 89 45 e4 74 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}