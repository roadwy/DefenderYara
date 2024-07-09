
rule Trojan_Win32_SmokeLoader_CT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 44 24 20 8b 44 24 20 89 44 24 18 8b 4c 24 10 33 4c 24 18 8b c6 c1 e8 05 51 03 c3 50 8d 54 24 18 52 89 4c 24 1c e8 [0-04] 8b 44 24 10 29 44 24 14 81 44 24 24 47 86 c8 61 83 ed 01 0f } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}