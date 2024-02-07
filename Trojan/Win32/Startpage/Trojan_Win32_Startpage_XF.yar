
rule Trojan_Win32_Startpage_XF{
	meta:
		description = "Trojan:Win32/Startpage.XF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 49 4e 49 41 3a } //01 00  dINIA:
		$a_01_1 = {25 73 5c 32 32 38 2e 74 6d 70 } //01 00  %s\228.tmp
		$a_01_2 = {5c 74 62 68 64 7a 2e 69 63 6f } //01 00  \tbhdz.ico
		$a_01_3 = {2e 00 4c 00 41 00 49 00 54 00 41 00 4f 00 2e 00 49 00 4e 00 46 00 4f 00 } //01 00  .LAITAO.INFO
		$a_03_4 = {25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 90 01 04 4f 4b 90 01 02 26 70 61 75 69 64 3d 90 01 01 26 6d 73 67 3d 90 01 03 26 74 69 6d 65 3d 90 01 02 25 64 2d 25 64 2d 25 64 5f 25 64 3a 25 64 3a 25 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}