
rule Trojan_Win32_Zusy_JKT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.JKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c9 0f b6 c3 0f af c8 8b 44 24 10 02 0c 28 32 d1 8b c8 41 89 4c 24 10 83 f9 04 7c e2 88 14 33 43 3b df 72 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}