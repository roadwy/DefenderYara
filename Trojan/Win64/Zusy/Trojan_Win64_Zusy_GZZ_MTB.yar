
rule Trojan_Win64_Zusy_GZZ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //01 00  taskkill /f /im ProcessHacker.exe
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 46 69 64 64 6c 65 72 45 76 65 72 79 77 68 65 72 65 2e 65 78 65 } //01 00  taskkill /f /im FiddlerEverywhere.exe
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4f 6c 6c 79 44 62 67 2e 65 78 65 } //01 00  taskkill /f /im OllyDbg.exe
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 49 64 61 36 34 2e 65 78 65 } //01 00  taskkill /f /im Ida64.exe
		$a_01_4 = {5c 5c 2e 5c 6b 70 72 6f 63 65 73 73 68 61 63 6b 65 72 } //01 00  \\.\kprocesshacker
		$a_01_5 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //00 00  cdn.discordapp.com/attachments
	condition:
		any of ($a_*)
 
}