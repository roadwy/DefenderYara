
rule Trojan_Win32_Redline_YRF_MTB{
	meta:
		description = "Trojan:Win32/Redline.YRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b 55 08 0f be 04 0a 8b 4d ?? 03 4d ?? 0f be 11 33 c2 88 45 ?? 8b 45 ?? 03 45 ?? 8a 08 88 4d ?? 0f be 55 ?? 0f be 45 ?? 03 d0 8b 4d ?? 03 4d ?? 88 11 0f be 55 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}