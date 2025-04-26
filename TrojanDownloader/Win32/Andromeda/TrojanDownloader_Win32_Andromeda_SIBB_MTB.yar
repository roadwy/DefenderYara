
rule TrojanDownloader_Win32_Andromeda_SIBB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Andromeda.SIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {56 56 53 ff d7 53 68 ?? ?? ?? ?? 56 50 ff 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 55 ?? a1 90 1b 02 8a 08 [0-80] 0f b6 c9 83 f1 ?? [0-80] 33 f6 39 35 90 1b 00 76 ?? a1 90 1b 02 8a 14 30 32 d1 80 c2 ?? 88 14 30 46 3b 35 90 1b 00 72 ?? [0-80] ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}