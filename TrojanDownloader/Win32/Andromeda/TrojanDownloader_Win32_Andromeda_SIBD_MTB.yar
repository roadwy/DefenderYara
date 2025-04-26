
rule TrojanDownloader_Win32_Andromeda_SIBD_MTB{
	meta:
		description = "TrojanDownloader:Win32/Andromeda.SIBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 50 6a 00 ff 55 ?? a3 ?? ?? ?? ?? [0-b0] 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 90 1b 01 ff 35 ?? ?? ?? ?? ff 55 ?? a1 90 1b 01 8a 00 88 45 ?? [0-b0] 0f b6 45 90 1b 09 8b 35 90 1b 01 33 c9 83 f0 ?? 39 0d 90 1b 03 76 ?? 8a 14 0e 32 d0 80 c2 ?? 88 14 0e 41 3b 0d 90 1b 03 72 ?? ff d6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}