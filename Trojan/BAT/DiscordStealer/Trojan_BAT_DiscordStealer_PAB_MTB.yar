
rule Trojan_BAT_DiscordStealer_PAB_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {63 61 6e 61 72 79 2e 64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f 31 30 36 39 32 32 32 36 38 31 35 35 37 33 33 36 30 36 34 2f } //canary.discord.com/api/webhooks/1069222681557336064/  2
		$a_80_1 = {64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f 38 33 37 37 36 32 35 36 34 32 34 36 36 30 31 37 33 38 2f } //discord.com/api/webhooks/837762564246601738/  2
		$a_80_2 = {70 61 73 73 77 6f 72 64 2d 63 72 79 70 74 65 64 2e 63 6f 63 6b 79 67 72 61 62 62 65 72 } //password-crypted.cockygrabber  1
		$a_01_3 = {47 65 74 41 6c 6c 50 61 73 73 77 6f 72 64 73 } //1 GetAllPasswords
		$a_01_4 = {47 65 74 41 6c 6c 43 6f 6f 6b 69 65 73 } //1 GetAllCookies
		$a_80_5 = {5c 54 65 6d 70 6f 72 61 72 79 5c 45 64 67 65 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //\Temporary\EdgePasswords.txt  1
		$a_80_6 = {5c 54 65 6d 70 6f 72 61 72 79 5c 45 64 67 65 43 6f 6f 6b 69 65 73 2e 74 78 74 } //\Temporary\EdgeCookies.txt  1
		$a_80_7 = {5c 54 65 6d 70 6f 72 61 72 79 5c 43 68 72 6f 6d 65 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //\Temporary\ChromePasswords.txt  1
		$a_80_8 = {5c 54 65 6d 70 6f 72 61 72 79 5c 43 68 72 6f 6d 65 43 6f 6f 6b 69 65 73 2e 74 78 74 } //\Temporary\ChromeCookies.txt  1
		$a_80_9 = {5c 54 65 6d 70 6f 72 61 72 79 5c 4f 70 65 72 61 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //\Temporary\OperaPasswords.txt  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}