
rule TrojanDownloader_BAT_Minecru_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Minecru.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 06 28 22 00 00 0a 06 6f 23 00 00 0a 6b 5a 22 00 00 ?? ?? 59 6b 6c 28 1e 00 00 0a b7 6f 24 00 00 0a 28 25 00 00 0a 28 26 00 00 0a 0b 09 17 d6 0d 09 1f ?? 31 ca } //1
		$a_01_1 = {51 00 57 00 45 00 52 00 54 00 59 00 55 00 49 00 4f 00 50 00 41 00 53 00 44 00 46 00 47 00 48 00 4a 00 4b 00 4c 00 5a 00 58 00 43 00 56 00 42 00 4e 00 4d 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 30 00 71 00 61 00 7a 00 78 00 73 00 77 00 65 00 64 00 63 00 76 00 66 00 72 00 74 00 67 00 62 00 6e 00 68 00 79 00 75 00 6a 00 6d 00 6b 00 69 00 6f 00 6c 00 70 00 } //1 QWERTYUIOPASDFGHJKLZXCVBNM1234567890qazxswedcvfrtgbnhyujmkiolp
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}