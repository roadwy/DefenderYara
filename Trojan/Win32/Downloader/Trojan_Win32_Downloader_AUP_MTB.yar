
rule Trojan_Win32_Downloader_AUP_MTB{
	meta:
		description = "Trojan:Win32/Downloader.AUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bf 2e c9 8c 00 41 81 e9 01 00 00 00 21 c9 e8 ?? ?? ?? ?? 68 82 02 39 5e 8b 04 24 83 c4 04 29 c1 81 e8 b9 83 17 26 31 3a 81 e8 9c 58 2b ad 01 c0 b9 52 df 29 7c 42 b8 e4 fa d0 5c 09 c8 39 f2 75 bf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}