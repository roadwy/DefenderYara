
rule Trojan_Win32_Tofsee_PVJ_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b c3 c1 e9 05 03 4d f4 c1 e0 04 03 45 f0 33 c8 8d 04 1e 33 c8 8d b6 47 86 c8 61 2b f9 83 6d 0c 01 75 90 01 01 8b 75 08 89 3e 5f 89 5e 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}