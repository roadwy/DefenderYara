
rule Trojan_Win32_TrickBotCrypt_GO_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 14 32 03 c2 33 d2 f7 35 90 01 04 2b 0d 90 01 04 0f af 0d 90 01 04 a1 90 01 04 41 0f af cf 03 d0 8b 44 24 18 03 ca 8a 10 8a 0c 31 32 d1 8b 4c 24 28 88 10 90 00 } //1
		$a_81_1 = {67 51 32 76 26 64 53 3e 36 70 39 55 77 31 25 39 4a 29 23 52 31 28 6f 2a 43 33 63 67 4c 43 31 76 46 68 4e 6a 30 32 28 6c 4e 43 65 4e 6b 6f 44 71 } //1 gQ2v&dS>6p9Uw1%9J)#R1(o*C3cgLC1vFhNj02(lNCeNkoDq
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}