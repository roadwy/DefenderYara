
rule Trojan_Win32_SystemBC_psyL_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {31 c0 83 c4 1c c2 04 00 90 8d b4 26 00 00 00 00 3d 94 00 00 c0 74 49 3d 96 00 00 c0 0f 84 89 00 00 00 3d 93 00 00 c0 75 d7 c7 44 24 04 00 00 00 00 c7 04 24 08 00 00 00 e8 8b 98 01 00 83 f8 01 0f 84 ad 00 00 00 85 c0 74 b6 c7 04 24 08 00 00 00 ff d0 b8 ff ff ff ff eb a8 } //00 00 
	condition:
		any of ($a_*)
 
}