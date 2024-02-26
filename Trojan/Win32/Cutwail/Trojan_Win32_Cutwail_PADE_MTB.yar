
rule Trojan_Win32_Cutwail_PADE_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.PADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 47 78 8b da 0f af c6 3b d0 74 25 8b 6f 40 69 c2 32 0a 00 00 89 44 24 1c 8b d0 2b ea 83 c3 03 89 6f 40 8b 47 78 0f af c6 3b d8 75 ee 8b 54 24 10 8b 47 2c 83 c1 03 33 c6 3b c8 76 c3 } //00 00 
	condition:
		any of ($a_*)
 
}