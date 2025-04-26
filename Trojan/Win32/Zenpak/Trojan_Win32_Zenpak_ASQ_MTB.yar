
rule Trojan_Win32_Zenpak_ASQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 02 6b c2 ?? 8b 4c 24 [0-04] 29 c1 89 c8 83 e8 02 89 4c 24 ?? 89 44 24 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}