
rule PWS_Win32_Frethog_GF{
	meta:
		description = "PWS:Win32/Frethog.GF,SIGNATURE_TYPE_PEHSTR,32 00 32 00 11 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 74 68 67 6f 65 72 } //10 Forthgoer
		$a_01_1 = {68 74 74 70 3a 2f 2f 32 33 64 72 66 2e 63 6f 6d 2f 78 6d 66 78 } //10 http://23drf.com/xmfx
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //10 System\CurrentControlSet\Services\
		$a_01_4 = {61 76 61 73 74 2e 73 65 74 75 70 } //1 avast.setup
		$a_01_5 = {41 56 50 2e 45 58 45 } //1 AVP.EXE
		$a_01_6 = {70 72 75 70 64 61 74 65 2e 70 70 6c } //1 prupdate.ppl
		$a_01_7 = {41 59 55 70 64 61 74 65 2e 61 79 65 } //1 AYUpdate.aye
		$a_01_8 = {50 6c 61 79 4f 6e 6c 69 6e 65 20 49 44 } //1 PlayOnline ID
		$a_01_9 = {70 6f 6c 2e 65 78 65 } //1 pol.exe
		$a_01_10 = {70 6f 6c 63 6f 72 65 2e 64 6c 6c } //1 polcore.dll
		$a_01_11 = {6d 61 70 6c 65 73 74 6f 72 79 2e 65 78 65 } //1 maplestory.exe
		$a_01_12 = {61 67 65 6f 66 63 6f 6e 61 6e 2e 65 78 65 } //1 ageofconan.exe
		$a_01_13 = {6c 6f 74 72 6f 63 6c 69 65 6e 74 2e 65 78 65 } //1 lotroclient.exe
		$a_01_14 = {74 75 72 62 69 6e 65 6c 61 75 6e 63 68 65 72 2e 65 78 65 } //1 turbinelauncher.exe
		$a_01_15 = {77 6f 77 2e 65 78 65 } //1 wow.exe
		$a_01_16 = {63 61 62 61 6c 6d 61 69 6e 2e 65 78 65 } //1 cabalmain.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=50
 
}