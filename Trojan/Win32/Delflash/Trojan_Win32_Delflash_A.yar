
rule Trojan_Win32_Delflash_A{
	meta:
		description = "Trojan:Win32/Delflash.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 8b c3 2d 87 9a 08 00 50 6a 00 8b c3 2d 89 9a 08 00 50 81 c3 76 65 f7 7f 53 8b 45 fc e8 90 01 04 50 ff 15 90 00 } //05 00 
		$a_00_1 = {b8 03 2c 32 0f 3d 14 ec cc 2a 0f 85 3a 02 00 00 } //01 00 
		$a_03_2 = {ff 47 43 4e 90 09 20 00 89 45 90 01 01 8a 03 8b 55 90 01 01 8b 4d 90 01 01 8a 94 0a 00 ff ff ff 88 13 8b 55 90 01 01 8b 4d 90 01 01 88 84 0a 00 ff ff 90 00 } //01 00 
		$a_01_3 = {42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //00 00  Borland\Delphi\
		$a_00_4 = {5d 04 00 00 37 21 } //03 80 
	condition:
		any of ($a_*)
 
}