
rule Trojan_Win32_Zenpak_AU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 48 b9 ab aa aa aa 89 44 24 44 f7 e1 c1 ea 03 6b c2 0c 8b 4c 24 44 29 c1 89 c8 83 e8 04 89 4c 24 40 89 44 24 3c 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}