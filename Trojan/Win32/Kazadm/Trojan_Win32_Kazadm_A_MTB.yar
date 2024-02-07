
rule Trojan_Win32_Kazadm_A_MTB{
	meta:
		description = "Trojan:Win32/Kazadm.A!MTB,SIGNATURE_TYPE_PEHSTR,19 00 19 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 53 6f 66 74 77 61 72 65 5c 4b 61 7a 61 61 5c 4c 6f 63 61 6c 43 6f 6e 74 65 6e 74 } //0a 00  \Software\Kazaa\LocalContent
		$a_01_1 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //01 00  FindFirstFileA
		$a_01_2 = {53 68 61 6b 69 72 61 20 46 75 6c 6c 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //01 00  Shakira FullDownloader.exe
		$a_01_3 = {47 6c 61 64 69 61 74 6f 72 20 46 75 6c 6c 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //01 00  Gladiator FullDownloader.exe
		$a_01_4 = {41 69 6b 61 51 75 65 73 74 33 48 65 6e 74 61 69 20 46 75 6c 6c 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //01 00  AikaQuest3Hentai FullDownloader.exe
		$a_01_5 = {4d 6f 76 69 65 7a 43 68 61 6e 6e 65 6c 73 49 6e 73 74 61 6c 65 72 2e 65 78 65 } //01 00  MoviezChannelsInstaler.exe
		$a_01_6 = {5a 69 64 61 6e 65 2d 53 63 72 65 65 6e 49 6e 73 74 61 6c 65 72 2e 65 78 65 } //01 00  Zidane-ScreenInstaler.exe
		$a_01_7 = {4c 6f 72 64 4f 66 54 68 65 52 69 6e 67 73 2d 46 75 6c 6c 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //01 00  LordOfTheRings-FullDownloader.exe
		$a_01_8 = {53 49 4d 53 20 46 75 6c 6c 44 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //01 00  SIMS FullDownloader.exe
		$a_01_9 = {42 72 69 74 6e 65 79 20 73 70 65 61 72 73 20 6e 75 64 65 2e 65 78 65 } //01 00  Britney spears nude.exe
		$a_01_10 = {51 75 61 6b 65 20 34 20 42 45 54 41 2e 65 78 65 } //01 00  Quake 4 BETA.exe
		$a_01_11 = {57 69 6e 64 6f 77 73 20 58 50 20 6b 65 79 20 67 65 6e 65 72 61 74 6f 72 2e 65 78 65 } //00 00  Windows XP key generator.exe
	condition:
		any of ($a_*)
 
}