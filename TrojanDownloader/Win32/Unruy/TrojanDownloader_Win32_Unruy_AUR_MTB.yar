
rule TrojanDownloader_Win32_Unruy_AUR_MTB{
	meta:
		description = "TrojanDownloader:Win32/Unruy.AUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 85 f6 7e 16 57 8a 11 6b c0 1f 0f be fa 03 c7 84 d2 75 01 4e 41 85 f6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}