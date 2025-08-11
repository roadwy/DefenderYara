
rule Trojan_BAT_RevengeRat_ARR_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0c 08 16 02 7b ?? 00 00 04 28 ?? 00 00 0a a2 08 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RevengeRat_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 13 07 28 ?? 00 00 0a 0d 19 13 07 17 28 ?? 00 00 0a 1f 20 17 19 15 28 ?? 00 00 0a 1a 13 07 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 0a 1b 13 07 17 12 00 15 6a 16 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RevengeRat_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 72 00 69 00 63 00 68 00 61 00 6c 00 71 00 75 00 65 00 5c 00 44 00 6f 00 66 00 75 00 73 00 } //1 Software\Orichalque\Dofus
		$a_01_1 = {4f 00 72 00 69 00 63 00 68 00 61 00 6c 00 71 00 75 00 65 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 } //1 Orichalqueupdater
		$a_01_2 = {4f 72 69 63 68 61 6c 71 75 65 2d 55 70 6c 61 75 6e 63 68 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4f 72 69 63 68 61 6c 71 75 65 75 70 64 61 74 65 72 2e 70 64 62 } //1 Orichalque-Uplauncher\obj\Release\Orichalqueupdater.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_RevengeRat_ARR_MTB_4{
	meta:
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 06 09 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 07 11 07 16 11 06 16 1f 10 28 ?? 00 00 0a 11 07 16 11 06 1f 0f 1f 10 28 ?? 00 00 0a 06 11 06 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 05 03 13 04 11 05 11 04 16 11 04 8e b7 6f ?? 00 00 0a 0c 08 0b de 0f } //1
		$a_01_1 = {43 00 41 00 43 00 41 00 4f 00 2e 00 74 00 72 00 6f 00 6c 00 6f 00 6c 00 6f 00 } //2 CACAO.trololo
		$a_01_2 = {42 00 45 00 54 00 49 00 53 00 45 00 } //3 BETISE
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=6
 
}
rule Trojan_BAT_RevengeRat_ARR_MTB_5{
	meta:
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 17 12 00 15 6a 16 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 17 9e 28 ?? 00 00 0a 02 06 02 7b ?? 00 00 04 28 ?? 00 00 0a 15 16 28 } //2
		$a_01_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 49 00 4d 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 taskkill /f /IM ProcessHacker.exe
		$a_01_2 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 49 00 4d 00 20 00 54 00 63 00 70 00 76 00 69 00 65 00 77 00 2e 00 65 00 78 00 65 00 } //1 taskkill /f /IM Tcpview.exe
		$a_01_3 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 49 00 4d 00 20 00 46 00 69 00 64 00 64 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 taskkill /f /IM Fiddler.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_BAT_RevengeRat_ARR_MTB_6{
	meta:
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0c 00 00 "
		
	strings :
		$a_03_0 = {16 0b 07 b5 1f 64 28 ?? ?? ?? 0a 0d 12 03 1f 64 14 13 04 12 04 1f 64 28 ?? ?? ?? 06 13 05 11 05 2c 08 ?? ?? ?? ?? ?? 0a de 28 00 00 07 17 d6 0b 07 1a 13 06 } //2
		$a_01_1 = {52 00 75 00 6e 00 46 00 69 00 6c 00 65 00 46 00 72 00 6f 00 6d 00 4c 00 69 00 6e 00 6b 00 } //1 RunFileFromLink
		$a_01_2 = {52 00 75 00 6e 00 46 00 69 00 6c 00 65 00 46 00 72 00 6f 00 6d 00 44 00 69 00 73 00 6b 00 } //1 RunFileFromDisk
		$a_01_3 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 48 00 6f 00 73 00 74 00 50 00 6f 00 72 00 74 00 } //1 EncryptHostPort
		$a_01_4 = {4d 00 65 00 73 00 73 00 67 00 62 00 6f 00 78 00 46 00 61 00 6b 00 65 00 43 00 68 00 65 00 63 00 6b 00 } //1 MessgboxFakeCheck
		$a_01_5 = {53 00 74 00 61 00 72 00 74 00 75 00 70 00 43 00 68 00 65 00 61 00 63 00 6b 00 } //1 StartupCheack
		$a_01_6 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 69 00 6e 00 53 00 68 00 75 00 6c 00 64 00 65 00 72 00 54 00 61 00 73 00 6b 00 } //1 InstallinShulderTask
		$a_01_7 = {53 00 43 00 48 00 54 00 61 00 73 00 6b 00 54 00 69 00 65 00 6d 00 } //1 SCHTaskTiem
		$a_01_8 = {48 00 69 00 64 00 65 00 41 00 66 00 74 00 65 00 72 00 52 00 75 00 6e 00 } //1 HideAfterRun
		$a_01_9 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 49 00 6e 00 6f 00 } //1 InstallIno
		$a_01_10 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 69 00 6e 00 6f 00 70 00 } //1 Installinop
		$a_01_11 = {52 65 76 65 6e 67 65 2d 52 41 54 } //3 Revenge-RAT
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*3) >=15
 
}