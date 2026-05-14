
rule Trojan_Win64_DiscordStealer_AHD_MTB{
	meta:
		description = "Trojan:Win64/DiscordStealer.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 67 65 74 44 69 73 63 6f 72 64 54 6f 6b 65 6e 46 69 6c 65 73 } //30 main.getDiscordTokenFiles
		$a_01_1 = {6d 61 69 6e 2e 72 65 67 65 78 53 65 61 72 63 68 54 6f 6b 65 6e 46 69 6c 65 73 } //10 main.regexSearchTokenFiles
		$a_01_2 = {6d 61 69 6e 2e 67 65 74 44 65 63 72 79 70 74 69 6f 6e 4b 65 79 } //20 main.getDecryptionKey
		$a_01_3 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 44 69 73 63 6f 72 64 54 6f 6b 65 6e } //40 main.decryptDiscordToken
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20+(#a_01_3  & 1)*40) >=100
 
}