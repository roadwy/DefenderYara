
rule Trojan_Win32_Redline_MVK_MTB{
	meta:
		description = "Trojan:Win32/Redline.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 ca 88 4d ?? 8b 45 ?? 03 45 ?? 8a 08 88 4d ?? 0f b6 55 ?? 8b 45 ?? 03 45 ?? 0f b6 08 03 ca 8b 55 ?? 03 55 ?? 88 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}