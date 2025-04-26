
rule Trojan_BAT_Zbot_CC_MTB{
	meta:
		description = "Trojan:BAT/Zbot.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 56 69 6d 65 57 6f 72 6c 64 2e 65 78 65 } //1 C:\VimeWorld.exe
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 76 6b 2e 63 6f 6d 2f 65 6e 74 68 68 61 63 6b 73 } //1 https://vk.com/enthhacks
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 2e 67 67 2f 46 45 72 37 64 7a 39 68 67 73 } //1 https://discord.gg/FEr7dz9hgs
		$a_01_3 = {65 6e 74 68 68 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d } //1 enthh.000webhostapp.com
		$a_01_4 = {6c 6f 67 2e 74 78 74 } //1 log.txt
		$a_01_5 = {62 61 73 65 36 34 5f 64 65 63 6f 64 65 } //1 base64_decode
		$a_01_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_7 = {43 68 65 61 74 } //1 Cheat
		$a_01_8 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_9 = {49 6e 6a 65 63 74 43 68 65 61 74 5f 4c 6f 61 64 } //1 InjectCheat_Load
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}