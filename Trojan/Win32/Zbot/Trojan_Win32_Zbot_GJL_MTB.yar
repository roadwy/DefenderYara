
rule Trojan_Win32_Zbot_GJL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c6 89 45 e4 69 c0 ?? ?? ?? ?? 35 ?? ?? ?? ?? 29 45 08 8b 45 08 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 45 f4 85 d2 0f 84 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}