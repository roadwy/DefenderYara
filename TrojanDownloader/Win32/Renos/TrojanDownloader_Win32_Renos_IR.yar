
rule TrojanDownloader_Win32_Renos_IR{
	meta:
		description = "TrojanDownloader:Win32/Renos.IR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 08 20 00 00 50 8d 85 90 01 02 ff ff 50 8b 85 90 01 02 ff ff 50 e8 90 00 } //01 00 
		$a_01_1 = {81 f8 0d f0 ad de 0f 84 } //00 00 
	condition:
		any of ($a_*)
 
}