
rule Trojan_Win32_Redline_YTB_MTB{
	meta:
		description = "Trojan:Win32/Redline.YTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 08 81 f2 9d 00 00 00 88 14 08 31 c0 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 81 f2 89 00 00 00 88 14 08 31 c0 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 04 8b 45 08 8b 4d fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}