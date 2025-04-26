
rule Trojan_Win32_Delflash_A{
	meta:
		description = "Trojan:Win32/Delflash.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 8b c3 2d 87 9a 08 00 50 6a 00 8b c3 2d 89 9a 08 00 50 81 c3 76 65 f7 7f 53 8b 45 fc e8 ?? ?? ?? ?? 50 ff 15 } //5
		$a_00_1 = {b8 03 2c 32 0f 3d 14 ec cc 2a 0f 85 3a 02 00 00 } //5
		$a_03_2 = {ff 47 43 4e 90 09 20 00 89 45 ?? 8a 03 8b 55 ?? 8b 4d ?? 8a 94 0a 00 ff ff ff 88 13 8b 55 ?? 8b 4d ?? 88 84 0a 00 ff ff } //1
		$a_01_3 = {42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //1 Borland\Delphi\
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*5+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}