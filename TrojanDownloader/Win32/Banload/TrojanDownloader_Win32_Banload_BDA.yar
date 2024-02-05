
rule TrojanDownloader_Win32_Banload_BDA{
	meta:
		description = "TrojanDownloader:Win32/Banload.BDA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 05 bf 01 00 00 00 8b 45 e4 33 db 8a 5c 38 ff 33 5d e0 3b 5d ec 7f 0b } //01 00 
		$a_01_1 = {54 53 69 74 69 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}