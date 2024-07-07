
rule TrojanDownloader_Win32_Upatre_V{
	meta:
		description = "TrojanDownloader:Win32/Upatre.V,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 3d 5a 5a 50 00 0f 85 90 01 04 8b 45 90 01 01 c1 e0 02 89 45 90 01 01 50 6a 08 ff 75 90 01 01 ff 55 90 01 01 85 c0 0f 84 90 01 04 89 45 90 01 01 8b 45 90 01 01 c1 e0 02 e8 00 00 00 00 59 83 c1 06 eb 90 01 01 52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 00 6e 74 64 6c 6c 2e 64 6c 6c 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}