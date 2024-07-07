
rule Trojan_Win32_Zbot_BG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 c4 8b 4d cc 8a 10 32 11 8b 45 c4 88 10 68 90 02 04 e8 90 02 04 83 c4 04 8b f0 68 90 02 04 e8 90 02 04 83 c4 04 3b f0 74 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}