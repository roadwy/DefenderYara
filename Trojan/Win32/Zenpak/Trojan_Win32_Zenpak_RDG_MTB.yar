
rule Trojan_Win32_Zenpak_RDG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f0 89 4d ec 89 55 e8 b8 3b 05 00 00 31 c9 89 45 e4 89 4d e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}