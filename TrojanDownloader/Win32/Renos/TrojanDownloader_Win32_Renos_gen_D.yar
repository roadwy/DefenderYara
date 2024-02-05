
rule TrojanDownloader_Win32_Renos_gen_D{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {65 6c 33 32 83 90 09 10 00 90 02 05 6b 65 72 6e 90 01 1b 90 02 08 54 ff 15 90 01 04 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}