
rule Trojan_Win32_Redline_CREU_MTB{
	meta:
		description = "Trojan:Win32/Redline.CREU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 9d d4 fe ff ff 0f b6 8c 1d e8 fe ff ff 88 8c 3d e8 fe ff ff 88 94 1d e8 fe ff ff 0f b6 8c 3d e8 fe ff ff 03 ce 0f b6 c9 0f b6 8c 0d e8 fe ff ff 32 88 90 01 04 88 88 90 01 04 c7 45 fc 90 01 04 40 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}