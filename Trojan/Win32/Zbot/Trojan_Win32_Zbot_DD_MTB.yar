
rule Trojan_Win32_Zbot_DD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {68 66 64 66 6a 64 6b 2e 65 78 65 } //hfdfjdk.exe  01 00 
		$a_81_1 = {63 65 2d 63 6c 6f 75 64 2e 63 6f 6d } //01 00 
		$a_80_2 = {69 6d 61 67 65 73 2f 6e 6f 74 65 63 68 2e 65 78 65 } //images/notech.exe  01 00 
		$a_80_3 = {64 64 6a 69 65 6e 6e 2e 65 78 65 } //ddjienn.exe  01 00 
		$a_80_4 = {55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 } //Updates downloader  01 00 
		$a_80_5 = {43 3a 5c 79 51 45 36 6e 63 6b 6f 2e 65 78 65 } //C:\yQE6ncko.exe  00 00 
	condition:
		any of ($a_*)
 
}