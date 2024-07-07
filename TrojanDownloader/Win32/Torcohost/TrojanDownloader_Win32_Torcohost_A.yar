
rule TrojanDownloader_Win32_Torcohost_A{
	meta:
		description = "TrojanDownloader:Win32/Torcohost.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 b7 81 e0 af 81 c2 f4 34 00 00 52 e8 90 01 04 85 c0 0f 85 90 01 01 00 00 00 90 02 07 8b 90 01 01 24 90 02 08 6b c9 90 04 01 02 63 69 05 f4 34 00 00 50 81 c1 90 01 02 41 00 51 e8 90 00 } //10
		$a_03_1 = {ff d2 50 8b 06 57 ff d0 85 c0 0f 84 90 01 02 00 00 8b 35 90 01 04 53 53 53 53 b9 90 01 04 e8 90 01 04 8b 8e 90 01 02 00 00 50 ff d1 89 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}