
rule Trojan_Win32_Zenpak_AR_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 39 8e e3 38 89 45 e4 f7 e1 c1 ea 02 6b c2 12 8b 4d e4 29 c1 89 c8 83 e8 02 89 4d e0 89 45 dc 74 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}