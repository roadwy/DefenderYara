
rule Trojan_Win32_Darkbot_GJT_MTB{
	meta:
		description = "Trojan:Win32/Darkbot.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 01 0f be 15 ?? ?? ?? ?? 33 ca 89 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8a 8c 05 ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 0f be 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8d 0c 42 8b 95 ?? ?? ?? ?? 88 8c 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}