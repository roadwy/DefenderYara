
rule Trojan_Win32_Fragtor_ENG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ENG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {60 e8 00 00 00 00 5d 81 ed 06 00 00 00 81 ed d0 1a 38 00 } //00 00 
	condition:
		any of ($a_*)
 
}