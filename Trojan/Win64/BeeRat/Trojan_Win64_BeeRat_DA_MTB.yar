
rule Trojan_Win64_BeeRat_DA_MTB{
	meta:
		description = "Trojan:Win64/BeeRat.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 53 63 72 65 65 6e 73 68 6f 74 } //1 main.Screenshot
		$a_81_1 = {6d 61 69 6e 2e 72 65 61 64 66 69 6c 65 } //1 main.readfile
		$a_81_2 = {6d 61 69 6e 2e 77 72 69 74 65 74 6f 66 69 6c 65 } //1 main.writetofile
		$a_81_3 = {6d 61 69 6e 2e 74 65 6c 65 67 72 61 6d 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 main.telegramNotification
		$a_81_4 = {74 65 6c 65 67 72 61 6d 2d 62 6f 74 } //1 telegram-bot
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}