
rule Trojan_Win32_Zenpak_AK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 6d 78 29 cc 89 44 24 30 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 30 29 c1 89 c8 83 e8 0e 89 4c 24 2c 89 44 24 28 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}