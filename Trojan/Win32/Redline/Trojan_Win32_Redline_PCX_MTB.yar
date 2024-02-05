
rule Trojan_Win32_Redline_PCX_MTB{
	meta:
		description = "Trojan:Win32/Redline.PCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e3 89 c8 c1 ea 90 01 01 6b d2 90 01 01 29 d0 0f b6 80 90 01 04 32 81 90 01 04 83 c1 01 83 f0 e5 88 81 90 01 04 81 f9 90 01 04 75 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}