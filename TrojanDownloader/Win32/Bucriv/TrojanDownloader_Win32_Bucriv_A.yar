
rule TrojanDownloader_Win32_Bucriv_A{
	meta:
		description = "TrojanDownloader:Win32/Bucriv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 7c 25 73 7c 25 64 7c 25 73 7c 25 73 7c 25 73 7c 25 73 } //01 00  1|%s|%d|%s|%s|%s|%s
		$a_03_1 = {04 53 0f 85 90 09 0b 00 80 90 03 01 01 3e 3f 41 0f 85 90 01 04 80 90 03 01 01 7e 7f 90 00 } //01 00 
		$a_01_2 = {56 68 00 00 00 80 56 56 8d 85 00 fe ff ff 50 57 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}