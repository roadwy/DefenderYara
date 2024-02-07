
rule TrojanDownloader_Win32_Kuluoz_D{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {c6 40 01 68 8b 4d 90 01 01 03 8d 90 01 02 ff ff 8b 55 90 01 01 89 51 02 8b 45 90 01 01 03 85 90 01 02 ff ff c6 40 06 c3 90 00 } //02 00 
		$a_01_1 = {3c 6b 6e 6f 63 6b 3e 3c 69 64 3e 25 73 3c 2f 69 64 3e } //01 00  <knock><id>%s</id>
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 5b 5e 3a 5d 3a 25 64 2f 25 73 } //01 00  http://%[^:]:%d/%s
		$a_01_3 = {25 31 30 32 34 5b 5e 3d 5d 3d 25 31 30 32 34 5b 5e 3b 5d } //00 00  %1024[^=]=%1024[^;]
	condition:
		any of ($a_*)
 
}