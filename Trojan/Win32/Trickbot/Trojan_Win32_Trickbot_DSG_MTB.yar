
rule Trojan_Win32_Trickbot_DSG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f4 33 d2 b9 0c 00 00 00 f7 f1 8b 45 e8 0f be 0c 10 8b 55 f4 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f4 88 81 ?? ?? ?? ?? 81 7d f4 04 2a 00 00 73 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}