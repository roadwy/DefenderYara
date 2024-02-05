
rule Trojan_Win32_Emotet_DCS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 33 d2 8a 07 8a 55 00 03 c2 b9 90 01 04 99 f7 f9 8b 4c 24 90 01 01 33 c0 90 00 } //01 00 
		$a_00_1 = {8b 4c 24 04 8b 54 24 08 56 8b c1 8b f2 0b ca f7 d0 f7 d6 0b c6 5e 23 c1 } //00 00 
	condition:
		any of ($a_*)
 
}