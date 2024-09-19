
rule TrojanDownloader_Win32_AsyncRat_G_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRat.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 4c 05 c9 32 ca 88 88 ?? ?? ?? ?? 40 83 f8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}