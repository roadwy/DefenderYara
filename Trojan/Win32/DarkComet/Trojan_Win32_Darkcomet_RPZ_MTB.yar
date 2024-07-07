
rule Trojan_Win32_Darkcomet_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Darkcomet.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b2 73 88 54 24 1e 88 54 24 1f b1 65 8d 54 24 18 52 8b f0 c6 44 24 1c 53 c6 44 24 1d 68 c6 44 24 1e 6f c6 44 24 1f 77 c6 44 24 20 4d 88 4c 24 21 c6 44 24 24 61 c6 44 24 25 67 88 4c 24 26 c6 44 24 27 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}