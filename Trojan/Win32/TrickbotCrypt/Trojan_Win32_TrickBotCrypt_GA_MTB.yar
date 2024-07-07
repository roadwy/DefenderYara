
rule Trojan_Win32_TrickBotCrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 14 8a 04 32 8b 54 24 18 8a 14 3a 88 14 0e 8b 54 24 1c 88 04 3a 0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 f7 f5 8b 6c 24 20 2b 15 90 01 04 0f b6 04 0a 30 44 2b ff 90 00 } //1
		$a_01_1 = {6f 6b 5f 79 61 34 3e 72 42 4d 77 57 73 31 5a 32 44 34 65 2a 3c 65 51 4e 3f 44 41 70 36 75 31 6d 62 21 2b 58 5e 72 3e 71 63 70 29 3f 6b 61 4a 4e 65 37 4f 66 69 71 70 70 23 6f 2a 48 5f 69 } //1 ok_ya4>rBMwWs1Z2D4e*<eQN?DAp6u1mb!+X^r>qcp)?kaJNe7Ofiqpp#o*H_i
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}