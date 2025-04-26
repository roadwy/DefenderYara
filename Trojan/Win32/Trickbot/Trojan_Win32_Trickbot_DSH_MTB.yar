
rule Trojan_Win32_Trickbot_DSH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 85 e4 d5 ff ff 33 d2 b9 [0-04] f7 f1 8b 45 f8 0f be 0c 10 8b 95 e4 d5 ff ff 0f b6 84 15 e8 d5 ff ff 33 c1 8b 8d e4 d5 ff ff 88 84 0d e8 d5 ff ff 81 bd e4 d5 ff ff 04 2a 00 00 73 11 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}