
rule Trojan_Win32_Killav_KV{
	meta:
		description = "Trojan:Win32/Killav.KV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c0 03 2b f7 99 46 f7 fe 8b c2 03 c7 } //01 00 
		$a_01_1 = {85 c0 74 07 8d 54 24 04 e9 69 08 00 00 } //01 00 
		$a_00_2 = {25 73 5c 52 25 63 6d 25 63 74 25 63 43 2e 64 6c 6c } //01 00  %s\R%cm%ct%cC.dll
		$a_00_3 = {5c 5f 6e 65 74 62 6f 74 5c 69 33 38 36 5c } //01 00  \_netbot\i386\
		$a_00_4 = {4b 69 53 65 72 76 69 63 65 4c 69 6d 69 74 3d 3d 25 30 38 58 } //01 00  KiServiceLimit==%08X
		$a_00_5 = {5c 5c 2e 5c 52 69 53 69 6e 67 32 30 30 38 } //00 00  \\.\RiSing2008
	condition:
		any of ($a_*)
 
}