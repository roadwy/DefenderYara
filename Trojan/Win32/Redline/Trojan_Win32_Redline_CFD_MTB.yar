
rule Trojan_Win32_Redline_CFD_MTB{
	meta:
		description = "Trojan:Win32/Redline.CFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 75 14 8b 45 08 0f be 04 10 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}