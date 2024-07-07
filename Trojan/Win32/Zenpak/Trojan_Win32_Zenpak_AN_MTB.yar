
rule Trojan_Win32_Zenpak_AN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc b9 6d 78 29 cc 89 45 f0 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4d f0 29 c1 89 c8 83 e8 0e 89 4d ec 89 45 e8 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}