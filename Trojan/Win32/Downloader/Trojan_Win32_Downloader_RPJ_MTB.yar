
rule Trojan_Win32_Downloader_RPJ_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {43 43 8b 32 42 42 42 42 8a 06 88 07 46 47 49 75 f7 0f b7 0b 81 f9 90 01 02 00 00 72 e4 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}