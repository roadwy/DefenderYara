
rule TrojanDownloader_Win32_Tiny_CRTD_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tiny.CRTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 b0 10 30 40 00 63 40 3d 8c 03 00 00 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}