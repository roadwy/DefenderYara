
rule TrojanDownloader_Win32_Srotgnat_A{
	meta:
		description = "TrojanDownloader:Win32/Srotgnat.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 e8 9f 00 00 00 53 e8 20 00 00 00 e8 36 00 00 00 53 e8 c2 ff ff ff 01 c3 80 3b 00 74 02 eb e0 31 c0 50 e8 b9 00 00 00 83 c4 04 c3 } //00 00 
	condition:
		any of ($a_*)
 
}