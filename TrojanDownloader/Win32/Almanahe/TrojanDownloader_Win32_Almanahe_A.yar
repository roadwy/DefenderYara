
rule TrojanDownloader_Win32_Almanahe_A{
	meta:
		description = "TrojanDownloader:Win32/Almanahe.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 85 ec fe ff ff 83 c0 01 89 85 ec fe ff ff 81 bd ec fe ff ff ?? ?? ?? ?? 7d 21 8b 8d ec fe ff ff 0f be 91 ?? ?? ?? ?? 81 f2 ff 00 00 00 8b 85 ec fe ff ff 88 90 90 ?? ?? ?? ?? eb c4 } //1
		$a_01_1 = {81 38 50 45 00 00 0f 85 d2 00 00 00 8b 4d dc 0f b7 51 14 8b 45 dc 8d 4c 10 18 89 8d d4 ef ff ff c7 45 fc 00 00 00 00 c7 85 d0 ef ff ff 00 00 00 00 eb 1e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}