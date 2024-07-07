
rule Trojan_BAT_Lazy_ALY_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ALY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 28 07 08 9a 0d 09 6f 85 00 00 0a 1c 33 17 09 6f 86 00 00 0a 17 33 0e 09 6f 87 00 00 0a 6f 1e 00 00 0a 0a 2b 0a 08 17 58 0c 08 07 8e 69 32 d2 } //2
		$a_01_1 = {4d 65 72 74 5c 44 65 73 6b 74 6f 70 5c 44 69 73 63 6f 72 64 54 65 6c 65 67 72 61 6d 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 44 69 73 63 6f 72 64 54 65 6c 65 67 72 61 6d 2e 70 64 62 } //1 Mert\Desktop\DiscordTelegram\obj\Release\DiscordTelegram.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Lazy_ALY_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.ALY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 08 13 04 16 13 05 2b 24 11 04 11 05 6f 90 01 03 0a 13 06 09 12 06 28 90 01 03 0a 72 9a 12 00 70 28 90 01 03 0a 0d 11 05 17 58 13 05 11 05 11 04 6f 90 01 03 0a 32 d1 09 09 6f 90 01 03 0a 17 59 17 90 00 } //2
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 69 00 73 00 20 00 6e 00 6f 00 77 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00 20 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 20 00 6f 00 66 00 20 00 74 00 68 00 69 00 73 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //1 Windows Logger is now running in the background of this system
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}