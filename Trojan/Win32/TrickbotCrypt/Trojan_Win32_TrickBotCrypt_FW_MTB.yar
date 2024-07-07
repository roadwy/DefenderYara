
rule Trojan_Win32_TrickBotCrypt_FW_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 8b 45 f4 2b c2 2b 05 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 55 0c 88 0c 02 90 00 } //5
		$a_81_1 = {74 50 2a 43 73 2a 3f 76 49 63 3c 67 4a 30 38 31 57 33 24 73 6c 5a 47 66 39 35 5f 56 4d 2b 6e 6b 78 59 76 33 6c 34 53 48 51 59 70 40 21 62 77 71 41 3e 4d 41 3c } //5 tP*Cs*?vIc<gJ081W3$slZGf95_VM+nkxYv3l4SHQYp@!bwqA>MA<
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*5) >=5
 
}