
rule Trojan_Win32_Zenpak_AS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc ba 6d 78 29 cc 89 45 c8 89 c8 f7 e2 c1 ea 08 69 c2 41 01 00 00 29 c1 89 c8 83 e8 13 89 4d c4 89 45 c0 74 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}