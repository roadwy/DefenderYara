
rule Trojan_Win32_Zenpak_ASI_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e1 c1 ea 03 6b c2 0c 8b 8c 24 d0 00 00 00 29 c1 89 c8 83 e8 02 89 4c 24 28 89 44 24 24 0f 84 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}