
rule Trojan_Win32_Cridex_DEC_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 69 c0 90 01 04 8d 14 55 90 01 04 8b cb 81 c6 90 01 04 89 75 00 83 c5 90 01 01 89 6c 24 90 01 01 2b c8 0f b7 c1 8b c8 69 c9 89 00 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}