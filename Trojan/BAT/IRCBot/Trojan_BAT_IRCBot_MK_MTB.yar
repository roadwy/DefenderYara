
rule Trojan_BAT_IRCBot_MK_MTB{
	meta:
		description = "Trojan:BAT/IRCBot.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 1c 28 89 00 00 0a 12 00 23 00 00 00 00 00 00 35 c0 28 84 00 00 0a 28 90 00 00 0a 2c 64 28 21 01 00 0a 6f 1a 01 00 0a 6f 26 01 00 0a 0b 20 b2 00 00 00 28 13 00 00 06 07 12 00 20 7c 01 00 00 28 13 00 00 06 28 8e 00 00 0a 28 6c 00 00 0a 0c 02 2c 07 } //20
		$a_01_1 = {d0 d6 00 00 01 2b 11 1f 7c 2b 14 20 18 01 00 00 14 14 14 2b 11 26 de 18 28 d1 00 00 0a 2b e8 28 13 00 00 06 2b e5 28 ce 00 00 0a 2b e8 } //15
		$a_01_2 = {48 75 6e 74 65 72 42 6f 74 20 2d 20 49 52 43 } //10 HunterBot - IRC
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10) >=45
 
}