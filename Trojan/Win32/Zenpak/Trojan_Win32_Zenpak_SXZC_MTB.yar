
rule Trojan_Win32_Zenpak_SXZC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SXZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 15 41 28 22 10 0f b6 35 42 28 22 10 31 f2 88 d0 a2 40 28 22 10 8b 15 24 28 22 10 81 ea e0 0e 00 00 89 15 24 28 22 10 c7 05 24 28 22 10 4e 0a 00 00 a0 40 28 22 10 88 45 f9 8a 45 f9 0f b6 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}