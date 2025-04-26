
rule Trojan_Linux_Gafgyt_C_xp{
	meta:
		description = "Trojan:Linux/Gafgyt.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_00_0 = {20 53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 20 30 6e 20 55 72 20 46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4c 33 33 54 20 48 61 78 45 72 53 } //2  Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS
		$a_00_1 = {63 6e 63 69 6e 70 75 74 } //1 cncinput
		$a_00_2 = {5f 73 63 61 6e 6e 65 72 } //1 _scanner
		$a_00_3 = {76 73 65 61 74 74 61 63 6b } //1 vseattack
		$a_00_4 = {4f 56 48 44 4f 57 4e 31 } //1 OVHDOWN1
		$a_00_5 = {6e 65 74 6c 69 6e 6b 5f 73 63 61 6e 6e 65 72 5f 6b 69 6c 6c } //1 netlink_scanner_kill
		$a_00_6 = {35 31 2e 32 35 34 2e 32 33 2e 32 33 37 3a } //1 51.254.23.237:
		$a_00_7 = {6c 58 66 59 43 37 54 46 61 43 71 35 48 76 39 38 32 77 75 49 69 4b 63 48 6c 67 46 41 30 6a 45 73 57 32 4f 46 51 53 74 4f 37 78 36 7a 4e 39 64 42 67 61 79 79 57 67 76 62 6b 30 4c 33 6c 5a 43 6c 7a 4a 43 6d 46 47 33 47 56 4e 44 46 63 32 69 54 48 4e 59 79 37 67 73 73 38 64 48 62 6f 42 64 65 4b 45 31 56 63 62 6c 48 31 41 78 72 56 79 69 71 6f 6b 77 32 52 59 46 76 64 34 63 64 31 51 78 79 61 48 61 77 77 50 36 67 6f 39 66 65 42 65 48 64 6c 76 4d 52 44 4c 62 45 62 74 79 33 50 79 38 79 56 54 33 55 54 6a 79 33 5a 4b 4f 4e 58 6d 4d 4e 76 55 52 54 55 5a 54 6b 65 48 33 37 58 54 39 48 35 4a 77 48 30 76 4b 42 31 59 77 32 72 53 59 6b } //2 lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1VcblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9feBeHdlvMRDLbEbty3Py8yVT3UTjy3ZKONXmMNvURTUZTkeH37XT9H5JwH0vKB1Yw2rSYk
		$a_00_8 = {53 54 44 48 45 58 } //1 STDHEX
		$a_00_9 = {62 69 6c 6c 79 62 6f 62 62 6f 74 2e 63 6f 6d 2f 63 72 61 77 6c 65 72 } //1 billybobbot.com/crawler
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*2+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=3
 
}