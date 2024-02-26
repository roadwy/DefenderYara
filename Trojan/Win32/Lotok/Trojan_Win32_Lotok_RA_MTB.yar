
rule Trojan_Win32_Lotok_RA_MTB{
	meta:
		description = "Trojan:Win32/Lotok.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {9d 66 49 60 90 02 06 61 32 06 60 90 02 08 61 88 07 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}