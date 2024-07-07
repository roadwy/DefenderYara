
rule Trojan_Win32_Trickbot_DSJ_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f1 8b 85 90 01 04 0f be 0c 10 8b 55 90 01 01 0f b6 84 15 90 01 04 33 c1 8b 4d 90 01 01 88 84 0d 90 01 04 81 7d 90 01 01 04 2a 00 00 73 90 09 0a 00 8b 45 90 01 01 33 d2 b9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}