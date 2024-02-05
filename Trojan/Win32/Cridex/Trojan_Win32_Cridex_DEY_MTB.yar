
rule Trojan_Win32_Cridex_DEY_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {80 e9 20 0f b6 c9 00 0d 90 01 04 8d 0c 40 81 c6 90 01 04 2b ca 8b 54 24 14 89 35 90 01 04 89 b4 2a 90 01 04 0f b6 3d 90 01 04 0f b7 c9 8d b4 40 90 01 04 0f b6 05 90 01 04 0f b7 d1 03 c7 2b f2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}