
rule Trojan_Win32_Qbot_RG_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 25 ff 00 00 00 0f b6 ?? ?? ?? ?? ?? 30 14 37 83 6c 24 ?? 01 8b 74 24 ?? 85 f6 } //2
		$a_02_1 = {81 e1 ff 00 00 00 8a 91 ?? ?? ?? ?? 0f b6 c2 03 05 ?? ?? ?? ?? 89 0d } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}