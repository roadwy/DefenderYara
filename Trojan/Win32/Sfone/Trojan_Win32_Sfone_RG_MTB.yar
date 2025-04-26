
rule Trojan_Win32_Sfone_RG_MTB{
	meta:
		description = "Trojan:Win32/Sfone.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {cb c2 3f 78 9e 06 fd 29 76 ca 57 f9 f5 04 18 c5 7f 93 b5 3f 09 c0 b2 67 b0 0f 4e 28 01 1d b0 11 dc 95 ad 44 03 25 d2 d7 07 8a a1 6f d3 a0 f4 39 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}