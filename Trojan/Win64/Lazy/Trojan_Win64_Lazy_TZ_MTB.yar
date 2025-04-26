
rule Trojan_Win64_Lazy_TZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.TZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //2 Go build ID:
		$a_81_1 = {54 68 75 6e 64 65 72 4b 69 74 74 79 2d 47 72 61 62 62 65 72 } //2 ThunderKitty-Grabber
		$a_81_2 = {74 6f 6b 65 6e 67 72 61 62 62 65 72 2e 53 65 74 54 65 6c 65 67 72 61 6d 43 72 65 64 65 6e 74 69 61 6c 73 } //2 tokengrabber.SetTelegramCredentials
		$a_81_3 = {74 6f 6b 65 6e 67 72 61 62 62 65 72 2e 69 6e 69 74 } //2 tokengrabber.init
		$a_81_4 = {74 6f 6b 65 6e 67 72 61 62 62 65 72 2e 53 65 6e 64 44 4d 56 69 61 41 50 49 } //2 tokengrabber.SendDMViaAPI
		$a_81_5 = {74 6f 6b 65 6e 67 72 61 62 62 65 72 2e 73 65 6e 64 4d 65 73 73 61 67 65 } //1 tokengrabber.sendMessage
		$a_81_6 = {64 65 66 65 6e 64 65 72 2e 44 69 73 61 62 6c 65 } //1 defender.Disable
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=12
 
}