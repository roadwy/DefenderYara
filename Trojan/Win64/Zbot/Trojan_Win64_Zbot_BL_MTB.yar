
rule Trojan_Win64_Zbot_BL_MTB{
	meta:
		description = "Trojan:Win64/Zbot.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 8b c2 8b c0 48 8b 4c 24 ?? 0f be 04 01 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f b6 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}