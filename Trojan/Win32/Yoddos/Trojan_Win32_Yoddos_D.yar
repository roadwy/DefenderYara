
rule Trojan_Win32_Yoddos_D{
	meta:
		description = "Trojan:Win32/Yoddos.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 75 6c 74 69 54 43 50 46 6c 6f 6f 64 00 } //01 00 
		$a_01_1 = {47 6f 6f 67 6c 65 62 6f 74 2f 32 2e 31 3b } //02 00 
		$a_03_2 = {b9 01 00 00 00 85 c9 74 57 83 3d 90 01 04 01 75 02 eb 4c b8 63 00 00 00 90 90 b8 9d ff ff ff 90 90 6a 06 6a 01 6a 02 ff 15 90 01 04 89 85 7c fd ff ff 6a 10 8d 55 f0 52 8b 85 7c fd ff ff 50 ff 15 90 01 04 b8 63 00 00 00 90 90 b8 9d ff ff ff 90 90 8b 8d 7c fd ff ff 51 ff 15 90 01 04 eb a0 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}