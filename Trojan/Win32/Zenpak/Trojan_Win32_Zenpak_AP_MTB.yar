
rule Trojan_Win32_Zenpak_AP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 6d 78 29 cc 89 44 24 38 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 38 29 c1 89 c8 83 e8 07 89 4c 24 34 89 44 24 30 74 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}