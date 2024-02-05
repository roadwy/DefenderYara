
rule Trojan_Win32_Redline_RE_MTB{
	meta:
		description = "Trojan:Win32/Redline.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 02 0f b6 00 0f b6 c0 88 45 90 01 01 c7 45 90 01 01 02 00 00 00 0f b6 45 90 01 01 8d 50 90 01 01 8b 45 90 01 01 83 90 01 02 31 d0 88 85 90 01 04 8d 85 90 01 04 83 c0 03 0f b6 00 0f b6 c0 88 45 90 01 01 c7 45 90 01 01 03 00 00 00 0f b6 45 90 01 01 8d 50 90 01 01 8b 45 90 01 01 83 90 01 02 31 d0 88 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}