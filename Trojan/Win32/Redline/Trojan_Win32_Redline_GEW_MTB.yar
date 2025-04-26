
rule Trojan_Win32_Redline_GEW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 10 6b c0 ?? 99 be ?? ?? ?? ?? f7 fe 83 e0 ?? 33 c8 88 4d ?? 0f be 4d ?? 0f be 55 ?? 03 ca 8b 45 ?? 03 45 ?? 88 08 0f be 4d ?? 8b 55 ?? 03 55 ?? 0f be 02 2b c1 8b 4d 0c 03 4d ?? 88 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}