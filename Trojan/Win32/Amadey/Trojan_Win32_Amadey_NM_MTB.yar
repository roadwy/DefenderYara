
rule Trojan_Win32_Amadey_NM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 b9 00 00 00 00 01 d9 31 01 59 5b 68 c4 da fe 6d 89 04 24 b8 00 00 00 00 05 01 d2 fd 7e 01 f0 2d 01 d2 fd 7e 01 18 58 68 00 8e 80 7b 89 0c 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}