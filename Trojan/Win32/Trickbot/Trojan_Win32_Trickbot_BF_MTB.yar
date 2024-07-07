
rule Trojan_Win32_Trickbot_BF_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 33 d2 f7 35 90 01 04 a1 90 01 04 89 6c 24 1c 0f af c6 8d 2c 49 2b e8 a1 90 01 04 0f af e9 0f af e9 03 d5 8d 0c 76 8d 04 82 2b c1 8a 0c 38 8b 44 24 1c 30 08 90 00 } //1
		$a_03_1 = {2b d1 8b c1 0f af d1 0f af c1 0f af d1 8d 2c f6 89 44 24 24 2b d5 8b 2d 90 01 04 03 54 24 14 03 c5 d1 e0 8b 6c 24 10 2b c6 0f be 14 1a 8d 04 43 03 ea 33 d2 0f b6 04 38 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}