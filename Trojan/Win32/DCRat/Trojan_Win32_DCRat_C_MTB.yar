
rule Trojan_Win32_DCRat_C_MTB{
	meta:
		description = "Trojan:Win32/DCRat.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {f7 f6 89 d1 8b 90 01 01 e4 8b 90 01 01 f4 01 d0 0f b6 00 89 c2 89 c8 31 d0 89 c1 8b 90 01 01 e4 8b 90 01 01 f4 01 d0 88 08 83 45 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}