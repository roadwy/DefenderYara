
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
		description = "Trojan:BAT/RevengeRat.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 72 00 69 00 63 00 68 00 61 00 6c 00 71 00 75 00 65 00 5c 00 44 00 6f 00 66 00 75 00 73 00 } //1 Software\Orichalque\Dofus
		$a_01_1 = {4f 00 72 00 69 00 63 00 68 00 61 00 6c 00 71 00 75 00 65 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 } //1 Orichalqueupdater
		$a_01_2 = {4f 72 69 63 68 61 6c 71 75 65 2d 55 70 6c 61 75 6e 63 68 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4f 72 69 63 68 61 6c 71 75 65 75 70 64 61 74 65 72 2e 70 64 62 } //1 Orichalque-Uplauncher\obj\Release\Orichalqueupdater.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_RevengeRat_ARR_MTB_3{
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