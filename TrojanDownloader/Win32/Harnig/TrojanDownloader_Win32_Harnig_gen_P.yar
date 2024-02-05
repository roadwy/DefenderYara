
rule TrojanDownloader_Win32_Harnig_gen_P{
	meta:
		description = "TrojanDownloader:Win32/Harnig.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 51 50 8b 45 fc 8b 08 8d 95 24 fd ff ff 52 8d 95 90 90 fe ff ff 52 50 ff 51 2c 90 01 08 81 bd cc fe ff ff 00 00 00 02 90 01 10 0f 01 4d f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}