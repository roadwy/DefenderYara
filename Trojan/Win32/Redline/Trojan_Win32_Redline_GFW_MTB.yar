
rule Trojan_Win32_Redline_GFW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 4d 80 0f b6 55 d7 f7 d2 8b 45 b8 33 c2 03 45 ac f7 d8 1b c0 83 c0 ?? 66 a3 ?? ?? ?? ?? 0f be 45 83 99 52 50 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GFW_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 99 bf ?? ?? ?? ?? f7 ff 25 ?? ?? ?? ?? 33 f0 03 ce 8b 55 ?? 03 55 ?? 88 0a 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f b6 11 2b d0 8b 45 ?? 03 45 ?? 88 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}