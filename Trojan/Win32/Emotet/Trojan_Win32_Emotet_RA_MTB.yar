
rule Trojan_Win32_Emotet_RA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {33 fa 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}