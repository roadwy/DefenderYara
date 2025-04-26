
rule Backdoor_Linux_Mirai_AY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 } //1 Self Rep Fucking NeTiS and Thisity
		$a_01_1 = {46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4c 33 33 54 20 48 61 78 45 72 53 } //1 FuCkInG FoReHeAd We BiG L33T HaxErS
		$a_01_2 = {55 73 65 72 2d 41 67 65 6e 74 } //1 User-Agent
		$a_01_3 = {69 6a 76 6f 6e } //1 ijvon
		$a_01_4 = {61 4a 50 4d 4f 47 } //1 aJPMOG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Backdoor_Linux_Mirai_AY_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.AY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {62 6f 74 2e 73 75 6e 6c 65 73 73 2e 6e 65 74 77 6f 72 6b } //1 bot.sunless.network
		$a_00_1 = {79 6f 75 72 20 64 65 76 69 63 65 20 67 6f 74 20 69 6e 66 65 63 74 65 64 20 62 79 20 73 75 6e 6c 65 73 73 20 49 47 20 40 69 6e 62 6f 61 74 7a 77 65 74 72 75 73 74 } //1 your device got infected by sunless IG @inboatzwetrust
		$a_00_2 = {66 6f 75 6e 64 20 6d 61 6c 77 61 72 65 20 73 74 72 69 6e 67 20 69 6e 20 63 6d 64 6c 69 6e 65 20 22 25 73 22 20 6b 69 6c 6c 69 6e 67 20 6e 6f 77 2e 20 70 69 64 } //1 found malware string in cmdline "%s" killing now. pid
		$a_00_3 = {73 63 61 6e 6c 69 73 74 65 6e 2e 73 75 6e 6c 65 73 73 2e 6e 65 74 77 6f 72 6b } //1 scanlisten.sunless.network
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}