
rule Trojan_Win64_Lazy_CZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.CZ!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 74 69 6c 73 2f 62 72 6f 77 73 65 72 73 2e 48 69 73 74 6f 72 79 } //1 utils/browsers.History
		$a_01_1 = {54 68 75 6e 64 65 72 4b 69 74 74 79 2d 47 72 61 62 62 65 72 2f 75 74 69 6c 73 2f 62 72 6f 77 73 65 72 73 2e 4c 6f 67 69 6e } //2 ThunderKitty-Grabber/utils/browsers.Login
		$a_01_2 = {54 68 75 6e 64 65 72 4b 69 74 74 79 2d 47 72 61 62 62 65 72 2f 75 74 69 6c 73 2f 74 6f 6b 65 6e 67 72 61 62 62 65 72 2e 69 6e 69 74 } //2 ThunderKitty-Grabber/utils/tokengrabber.init
		$a_01_3 = {62 72 6f 77 73 65 72 73 2e 64 61 74 61 42 6c 6f 62 } //1 browsers.dataBlob
		$a_01_4 = {64 65 66 65 6e 64 65 72 2e 44 69 73 61 62 6c 65 } //1 defender.Disable
		$a_01_5 = {62 72 6f 77 73 65 72 73 2e 43 72 65 64 69 74 43 61 72 64 } //1 browsers.CreditCard
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}