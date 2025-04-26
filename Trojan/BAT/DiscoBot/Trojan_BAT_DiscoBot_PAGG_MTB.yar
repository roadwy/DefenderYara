
rule Trojan_BAT_DiscoBot_PAGG_MTB{
	meta:
		description = "Trojan:BAT/DiscoBot.PAGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {2e 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 } //1 .passwords
		$a_00_1 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 44 00 69 00 73 00 6b 00 44 00 72 00 69 00 76 00 65 00 } //1 select * from Win32_DiskDrive
		$a_01_2 = {64 69 73 63 6f 72 64 42 6f 74 } //2 discordBot
		$a_01_3 = {54 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 } //1 TakeScreenshot
		$a_00_4 = {4b 00 65 00 79 00 20 00 44 00 6f 00 77 00 6e 00 3a 00 20 00 7b 00 30 00 7d 00 20 00 61 00 74 00 20 00 7b 00 31 00 7d 00 } //2 Key Down: {0} at {1}
		$a_00_5 = {4d 00 6f 00 75 00 73 00 65 00 20 00 43 00 6c 00 69 00 63 00 6b 00 3a 00 } //2 Mouse Click:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=9
 
}