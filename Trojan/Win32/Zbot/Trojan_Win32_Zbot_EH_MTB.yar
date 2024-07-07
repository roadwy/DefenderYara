
rule Trojan_Win32_Zbot_EH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 33 d2 f7 f7 89 45 08 8d 42 37 83 fa 09 77 03 8d 42 30 88 01 41 83 7d 08 00 77 e2 8b c1 2b c6 c6 01 00 49 8a 1e 8a 11 88 19 49 88 16 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}