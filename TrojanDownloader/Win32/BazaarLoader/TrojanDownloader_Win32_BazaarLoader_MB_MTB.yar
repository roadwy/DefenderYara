
rule TrojanDownloader_Win32_BazaarLoader_MB_MTB{
	meta:
		description = "TrojanDownloader:Win32/BazaarLoader.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 54 3d ec 8d 76 02 8a ca b0 90 01 01 c0 e9 90 01 01 80 e2 90 01 01 3a c1 1a c0 24 90 01 01 04 90 01 01 02 c1 88 46 fe b0 90 01 01 3a c2 1a c0 47 24 90 01 01 04 90 01 01 02 c2 88 46 ff 83 ff 90 01 01 72 cd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}