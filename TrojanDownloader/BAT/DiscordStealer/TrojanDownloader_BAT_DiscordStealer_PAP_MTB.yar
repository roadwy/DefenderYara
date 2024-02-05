
rule TrojanDownloader_BAT_DiscordStealer_PAP_MTB{
	meta:
		description = "TrojanDownloader:BAT/DiscordStealer.PAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 36 35 31 35 32 32 33 38 32 32 30 30 31 37 36 36 39 30 2f 36 36 30 39 38 34 37 39 32 30 36 31 33 31 33 30 32 34 2f 6d 61 70 70 65 72 5f 33 2e 65 78 65 } //cdn.discordapp.com/attachments/651522382200176690/660984792061313024/mapper_3.exe  01 00 
		$a_80_1 = {63 6d 64 2e 65 78 65 } //cmd.exe  01 00 
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  01 00 
		$a_80_3 = {52 65 73 65 74 2d 50 68 79 73 69 63 61 6c 44 69 73 6b } //Reset-PhysicalDisk  01 00 
		$a_80_4 = {43 3a 5c 5c 57 69 6e 64 6f 77 73 5c 5c 49 4d 45 5c 5c 6d 61 70 70 65 72 2e 65 78 65 } //C:\\Windows\\IME\\mapper.exe  01 00 
		$a_80_5 = {53 70 6f 6f 66 69 6e 67 20 44 69 73 6b 64 72 69 76 65 21 } //Spoofing Diskdrive!  00 00 
	condition:
		any of ($a_*)
 
}