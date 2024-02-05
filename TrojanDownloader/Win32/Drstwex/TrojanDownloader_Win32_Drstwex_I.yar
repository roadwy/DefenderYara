
rule TrojanDownloader_Win32_Drstwex_I{
	meta:
		description = "TrojanDownloader:Win32/Drstwex.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 18 5b 58 e2 bd e9 b3 f0 ff ff 59 5e a1 79 0d 16 00 90 8a 1e 90 32 d8 90 88 1e 90 eb d2 } //00 00 
	condition:
		any of ($a_*)
 
}