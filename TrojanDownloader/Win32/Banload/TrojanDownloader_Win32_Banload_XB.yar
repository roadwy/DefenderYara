
rule TrojanDownloader_Win32_Banload_XB{
	meta:
		description = "TrojanDownloader:Win32/Banload.XB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 61 76 65 00 00 00 ff ff ff ff 01 00 00 00 24 00 00 00 55 8b ec 81 c4 04 f0 ff ff 50 81 c4 e8 fc ff ff } //00 00 
	condition:
		any of ($a_*)
 
}