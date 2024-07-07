
rule Trojan_Win32_ClipBanker_DJ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_1 = {6d 61 69 6e 2e 48 69 64 65 57 69 6e 64 6f 77 } //1 main.HideWindow
		$a_01_2 = {6d 61 69 6e 2e 63 72 65 61 74 65 57 61 6c 6c 65 74 73 } //1 main.createWallets
		$a_01_3 = {63 72 79 70 74 6f 53 74 65 61 6c 65 72 2f 70 72 6f 63 63 65 73 73 36 34 2f 6d 61 69 6e 2e 67 6f } //1 cryptoStealer/proccess64/main.go
		$a_01_4 = {70 72 6f 63 63 65 73 73 36 34 2f 64 6f 6d 61 69 6e 2f 41 70 70 2f 72 65 70 6c 61 63 65 2e 52 65 70 6c 61 63 65 57 61 6c 6c 65 74 } //1 proccess64/domain/App/replace.ReplaceWallet
		$a_01_5 = {67 69 74 68 75 62 2e 63 6f 6d 2f 67 6f 2d 74 65 6c 65 67 72 61 6d 2d 62 6f 74 2d 61 70 69 2f 74 65 6c 65 67 72 61 6d 2d 62 6f 74 2d 61 70 69 } //1 github.com/go-telegram-bot-api/telegram-bot-api
		$a_01_6 = {67 69 74 68 75 62 2e 63 6f 6d 2f 61 74 6f 74 74 6f 2f 63 6c 69 70 62 6f 61 72 64 2e 57 72 69 74 65 41 6c 6c } //1 github.com/atotto/clipboard.WriteAll
		$a_01_7 = {67 69 74 68 75 62 2e 63 6f 6d 2f 41 6c 6c 65 6e 44 61 6e 67 2f 77 33 32 } //1 github.com/AllenDang/w32
		$a_01_8 = {67 69 74 68 75 62 2e 63 6f 6d 2f 74 65 63 68 6e 6f 77 65 65 6e 69 65 2f 6d 75 6c 74 69 70 61 72 74 73 74 72 65 61 6d 65 72 } //1 github.com/technoweenie/multipartstreamer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}