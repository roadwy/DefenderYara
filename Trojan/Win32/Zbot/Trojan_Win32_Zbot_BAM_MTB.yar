
rule Trojan_Win32_Zbot_BAM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 cc 33 d2 b9 10 00 00 00 f7 f1 8b 45 cc 8a 88 ?? ?? ?? ?? 2a 8a ?? ?? ?? ?? 8b 55 cc 88 8a ?? ?? ?? ?? eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}