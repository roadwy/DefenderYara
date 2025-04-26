
rule Trojan_Win32_Zenpak_AT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 5c b9 [0-04] 89 44 24 58 f7 e1 c1 ea 03 6b c2 0c 8b 4c 24 58 29 c1 89 c8 83 e8 09 89 4c 24 54 89 44 24 50 74 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}