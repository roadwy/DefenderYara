
rule Trojan_Win32_Downloader_ADE_MTB{
	meta:
		description = "Trojan:Win32/Downloader.ADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 85 98 fe ff ff 83 f0 14 c7 85 9c fe ff ff 01 00 00 00 8b 8d 9c fe ff ff 89 85 78 fe ff ff 83 f1 00 89 8d 7c fe ff ff c7 85 88 fe ff ff 14 00 00 00 c7 85 8c fe ff ff 00 00 00 00 c7 85 90 fe ff ff d9 0d 01 00 c7 85 94 fe ff ff 00 00 00 00 c7 85 80 fe ff ff 52 67 00 00 c7 85 84 fe ff ff 00 00 00 00 8b 95 90 fe ff ff 8b bd 94 fe ff ff 8b 85 88 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}