
rule TrojanDownloader_Win32_Nurech_S{
	meta:
		description = "TrojanDownloader:Win32/Nurech.S,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 8b f0 c6 45 fc 7e e8 90 01 02 ff ff 50 8d 45 ec ff 36 68 90 01 02 40 00 50 90 00 } //01 00 
		$a_03_1 = {c6 45 fc 57 50 e8 90 01 02 ff ff 83 c4 0c ff 30 8d 85 90 01 01 ff ff ff c6 45 fc 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}