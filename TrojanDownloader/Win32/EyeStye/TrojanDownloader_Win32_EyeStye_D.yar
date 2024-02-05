
rule TrojanDownloader_Win32_EyeStye_D{
	meta:
		description = "TrojanDownloader:Win32/EyeStye.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 8b 0e 89 01 8b 06 83 38 00 74 cf } //01 00 
		$a_01_1 = {03 f3 30 06 43 3b 5d 10 72 bc 8b 45 08 } //01 00 
		$a_01_2 = {77 61 69 74 63 6f 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}