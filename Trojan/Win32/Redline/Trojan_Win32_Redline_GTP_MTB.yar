
rule Trojan_Win32_Redline_GTP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea 03 45 ?? 89 45 ?? 8b 45 ?? 03 55 ?? 03 c7 89 45 ?? 8b 45 ?? 31 45 ?? 31 55 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}