
rule TrojanDownloader_Win32_Delevid_A{
	meta:
		description = "TrojanDownloader:Win32/Delevid.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 90 01 01 8d 45 f4 8b d3 e8 90 01 02 ff ff 8b 55 f4 8b c7 e8 90 01 02 ff ff ff 45 f8 4e 75 d9 90 00 } //01 00 
		$a_03_1 = {c6 44 18 05 6d 8d 45 fc e8 90 01 02 ff ff c6 44 18 06 33 8d 45 fc e8 90 01 02 ff ff c6 44 18 07 32 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}