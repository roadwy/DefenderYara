
rule Trojan_Win32_Stealerc_GAB_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {c1 f9 02 33 c1 0f b7 15 90 01 04 c1 fa 03 33 c2 0f b7 0d 90 01 04 c1 f9 05 33 c1 83 e0 01 a3 90 01 04 0f b7 15 90 01 04 d1 fa a1 90 01 04 c1 e0 0f 0b d0 66 89 15 90 01 04 0f b7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}