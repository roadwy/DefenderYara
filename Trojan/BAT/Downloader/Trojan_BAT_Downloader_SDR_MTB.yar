
rule Trojan_BAT_Downloader_SDR_MTB{
	meta:
		description = "Trojan:BAT/Downloader.SDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,42 00 42 00 0b 00 00 "
		
	strings :
		$a_81_0 = {52 65 76 65 72 73 65 } //10 Reverse
		$a_81_1 = {47 65 74 41 73 73 65 6d 62 6c 69 65 73 } //10 GetAssemblies
		$a_81_2 = {47 65 74 54 79 70 65 73 } //10 GetTypes
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 73 } //10 GetMethods
		$a_81_4 = {49 6e 76 6f 6b 65 } //10 Invoke
		$a_81_5 = {54 6f 41 72 72 61 79 } //10 ToArray
		$a_01_6 = {2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 62 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 } //2 /c ping bing.com
		$a_01_7 = {2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00 } //2 /c ping yahoo.com
		$a_80_8 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d } //cdn.discordapp.com  4
		$a_80_9 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 42 53 6c 47 6d 38 2f 53 4b 4d 2d 32 30 30 31 31 31 32 31 30 30 2e 70 6e 67 } //transfer.sh/get/BSlGm8/SKM-2001112100.png  4
		$a_80_10 = {65 73 61 6c 6f 67 2d 62 67 2e 63 6f 6d 2f 69 6d 61 67 65 73 31 2f 62 6f 6f 6b 2f 67 69 67 2f 61 2f 43 72 69 79 6f 70 2e 6a 70 67 } //esalog-bg.com/images1/book/gig/a/Criyop.jpg  4
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_80_8  & 1)*4+(#a_80_9  & 1)*4+(#a_80_10  & 1)*4) >=66
 
}