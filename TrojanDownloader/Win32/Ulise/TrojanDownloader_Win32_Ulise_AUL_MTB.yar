
rule TrojanDownloader_Win32_Ulise_AUL_MTB{
	meta:
		description = "TrojanDownloader:Win32/Ulise.AUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c1 be e8 03 00 00 f7 f6 69 d2 e8 03 00 00 89 45 f8 89 55 fc 33 f6 46 41 f7 d9 1b c9 8d 45 f8 23 c8 51 6a 00 6a 00 8d 85 f4 fe ff ff 50 6a 00 89 b5 f4 fe ff ff 89 bd f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}