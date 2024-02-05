
rule Trojan_Win32_SuperBearRat_AVKF_MTB{
	meta:
		description = "Trojan:Win32/SuperBearRat.AVKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 68 00 04 00 00 8b 55 b4 52 8b 45 c0 8b 08 51 } //00 00 
	condition:
		any of ($a_*)
 
}