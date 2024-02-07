
rule Trojan_Win32_Alureon_GC{
	meta:
		description = "Trojan:Win32/Alureon.GC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 5b 5e 2e 5d 2e 25 5b 5e 28 5d 28 25 5b 5e 29 5d 29 } //01 00  %[^.].%[^(](%[^)])
		$a_03_1 = {8b 75 08 80 7e 14 00 75 90 01 01 8b 4e 08 8d 46 24 50 6a 00 68 3f 00 0f 00 c6 46 14 01 ff d1 90 00 } //01 00 
		$a_01_2 = {0f b7 46 04 b9 64 86 00 00 66 3b c1 75 06 8b 4a 08 29 4e 50 b9 4c 01 00 00 66 3b c1 75 06 8b 42 08 29 46 50 33 c0 6a 0a 59 8b fa f3 ab b8 ff ff 00 00 66 01 46 06 } //00 00 
	condition:
		any of ($a_*)
 
}