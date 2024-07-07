
rule Trojan_Win32_Zenpak_AM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 6d 78 29 cc 8b 4c 24 50 89 44 24 4c 89 c8 8b 54 24 4c f7 e2 c1 ea 08 69 c2 41 01 00 00 29 c1 89 c8 83 e8 06 89 4c 24 48 89 44 24 44 74 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}