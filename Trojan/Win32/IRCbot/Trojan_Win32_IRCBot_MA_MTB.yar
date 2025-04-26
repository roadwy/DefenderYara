
rule Trojan_Win32_IRCBot_MA_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 03 c0 03 46 24 33 d2 52 50 a1 ?? ?? ?? ?? 99 03 04 24 13 54 24 04 83 c4 08 66 8b 00 66 25 ff ff 0f b7 c0 c1 e0 02 03 46 1c 33 d2 52 50 a1 ?? ?? ?? ?? 99 03 04 24 13 54 24 04 83 c4 08 8b 00 03 05 ?? ?? ?? ?? 89 45 f8 43 83 7d f8 00 75 ?? 3b 5e 18 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}