
rule Trojan_Win32_Slepak_DEC_MTB{
	meta:
		description = "Trojan:Win32/Slepak.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c0 2b c1 05 c5 8f 00 00 03 c3 a3 90 01 04 0f b7 05 90 01 04 80 c3 5c 02 da 02 da 88 1d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}