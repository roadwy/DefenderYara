
rule Trojan_Win32_Redline_GEN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d9 03 f9 81 a4 94 90 01 04 8d 65 01 27 c1 c0 17 89 bc 14 90 01 04 c3 e8 90 01 04 c7 44 24 90 01 01 14 a6 2e c9 8b 44 25 90 01 01 c7 04 24 90 00 } //01 00 
		$a_01_1 = {50 40 2e 65 68 5f 66 72 61 6d } //00 00 
	condition:
		any of ($a_*)
 
}