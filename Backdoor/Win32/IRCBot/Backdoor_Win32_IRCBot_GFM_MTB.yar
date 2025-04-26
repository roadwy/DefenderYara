
rule Backdoor_Win32_IRCBot_GFM_MTB{
	meta:
		description = "Backdoor:Win32/IRCBot.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 cc 8d 4d de 89 e0 89 08 e8 ?? ?? ?? ?? 89 c1 8b 45 cc 99 f7 f9 8a 4c 15 de 8b 45 d4 88 4c 05 de 8b 45 d4 83 c0 01 89 45 d4 } //10
		$a_01_1 = {61 6c 73 6b 64 6a 66 68 34 35 36 67 76 74 62 65 37 38 39 6e 77 6d 71 7a 75 78 69 63 6f 70 31 32 33 } //1 alskdjfh456gvtbe789nwmqzuxicop123
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}