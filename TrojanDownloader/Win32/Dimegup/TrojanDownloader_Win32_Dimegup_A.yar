
rule TrojanDownloader_Win32_Dimegup_A{
	meta:
		description = "TrojanDownloader:Win32/Dimegup.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 6d 5f 65 64 69 74 65 72 72 6f 72 2e 74 6d 70 } //01 00  \m_editerror.tmp
		$a_00_1 = {68 74 74 70 3a 2f 2f 6e 65 74 77 6f 72 6b 73 65 63 75 72 69 74 79 78 2e 68 6f 70 74 6f 2e 6f 72 67 } //01 00  http://networksecurityx.hopto.org
		$a_00_2 = {78 78 78 78 5f 78 78 78 78 5f 78 78 78 78 } //01 00  xxxx_xxxx_xxxx
		$a_01_3 = {8b c7 33 d2 f7 75 14 8b 45 0c 0f b6 04 02 03 06 03 c3 8b d9 99 f7 fb 8a 06 47 88 45 ff 8b da } //01 00 
	condition:
		any of ($a_*)
 
}