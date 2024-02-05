
rule Trojan_Win32_Downloader_RPG_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f 3f 07 0b c7 45 84 00 00 00 00 c7 45 fc ff ff ff } //01 00 
		$a_01_1 = {56 4d 77 61 72 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Downloader_RPG_MTB_2{
	meta:
		description = "Trojan:Win32/Downloader.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6f 77 65 72 53 68 65 6c 6c } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {49 00 48 00 4e 00 68 00 62 00 43 00 42 00 68 00 49 00 45 00 35 00 6c 00 64 00 79 00 31 00 50 00 59 00 } //01 00 
		$a_01_3 = {2d 00 77 00 68 00 61 00 74 00 74 00 } //01 00 
		$a_01_4 = {2d 00 65 00 78 00 74 00 64 00 75 00 6d 00 6d 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}