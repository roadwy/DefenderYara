
rule Trojan_Win32_Mokes_B_MTB{
	meta:
		description = "Trojan:Win32/Mokes.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 44 24 1c 76 00 2e 00 90 02 09 c7 44 24 90 01 01 7a 00 67 00 90 02 09 c7 44 24 90 01 01 65 00 76 00 c7 44 24 90 01 01 2f 00 25 00 c7 44 24 90 01 01 64 00 2e 00 c7 44 24 90 01 01 6d 00 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}