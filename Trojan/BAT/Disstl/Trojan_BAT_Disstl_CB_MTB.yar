
rule Trojan_BAT_Disstl_CB_MTB{
	meta:
		description = "Trojan:BAT/Disstl.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {50 6c 65 61 73 65 20 47 6f 20 54 6f 20 23 64 6f 77 6e 6c 6f 61 64 73 20 49 6e 20 54 68 65 20 44 69 73 63 6f 72 64 20 41 6e 64 20 44 6f 77 6e 6c 6f 61 64 20 54 68 65 20 4e 65 77 20 56 65 72 69 73 6f 6e } //1 Please Go To #downloads In The Discord And Download The New Verison
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 } //1 https://pastebin.com/raw
		$a_01_2 = {24 63 37 38 65 35 37 35 37 2d 34 35 39 37 2d 34 38 37 61 2d 62 63 65 61 2d 39 35 33 38 34 30 33 64 39 36 65 36 } //1 $c78e5757-4597-487a-bcea-9538403d96e6
		$a_81_3 = {59 4f 55 20 43 41 4e 20 47 45 54 20 42 41 4e 4e 45 44 20 46 52 4f 4d 20 54 48 45 20 42 4f 54 20 55 53 49 4e 47 20 54 48 49 53 20 42 45 20 53 41 46 45 } //1 YOU CAN GET BANNED FROM THE BOT USING THIS BE SAFE
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_5 = {64 69 73 63 6f 72 64 2e 67 67 } //1 discord.gg
		$a_01_6 = {43 3a 5c 55 73 65 72 73 5c 64 61 77 6e 73 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 5a 78 6e 6f 27 73 20 44 69 73 63 6f 72 64 20 54 6f 6f 6c 73 5c 6f 62 6a 5c 44 65 62 75 67 5c 5a 78 6e 6f 27 73 20 44 69 73 63 6f 72 64 20 54 6f 6f 6c 73 2e 70 64 62 } //1 C:\Users\dawns\source\repos\Zxno's Discord Tools\obj\Debug\Zxno's Discord Tools.pdb
		$a_01_7 = {44 69 73 63 6f 72 64 57 65 62 68 6f 6f 6b 50 72 6f 66 69 6c 65 } //1 DiscordWebhookProfile
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}