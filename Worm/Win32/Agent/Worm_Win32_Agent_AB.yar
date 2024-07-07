
rule Worm_Win32_Agent_AB{
	meta:
		description = "Worm:Win32/Agent.AB,SIGNATURE_TYPE_PEHSTR,ffffff8d 00 ffffff8d 00 0a 00 00 "
		
	strings :
		$a_01_0 = {8b c1 8b f7 33 cb 03 f0 03 f9 83 f1 ff 83 f0 ff 33 cf 33 c6 83 c2 04 81 e1 00 01 01 81 } //100
		$a_01_1 = {53 65 74 75 70 2e 7a 69 70 2e 65 78 65 } //10 Setup.zip.exe
		$a_01_2 = {70 32 70 65 78 2e 7a 69 70 2e 65 78 65 } //10 p2pex.zip.exe
		$a_01_3 = {77 77 77 2e 72 65 67 69 6f 6e 65 2e 63 61 6c 61 62 72 69 61 2e 69 74 } //10 www.regione.calabria.it
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {59 6f 75 20 41 72 65 20 45 6d 70 74 79 2e 7a 69 70 2e 65 78 65 } //1 You Are Empty.zip.exe
		$a_01_6 = {57 69 6e 64 6f 77 73 20 58 70 20 6f 6e 20 50 73 50 2e 7a 69 70 2e 65 78 65 } //1 Windows Xp on PsP.zip.exe
		$a_01_7 = {48 61 6c 66 20 4c 69 66 65 20 32 20 45 70 69 73 6f 64 65 20 4f 6e 65 2e 7a 69 70 2e 65 78 65 } //1 Half Life 2 Episode One.zip.exe
		$a_01_8 = {44 4f 4f 4d 20 33 20 46 75 6c 6c 20 33 20 43 44 20 42 6f 6e 75 73 2e 7a 69 70 2e 65 78 65 } //1 DOOM 3 Full 3 CD Bonus.zip.exe
		$a_01_9 = {57 69 6e 64 6f 77 73 20 56 69 73 74 61 20 55 6c 74 69 6d 61 74 65 20 53 50 33 20 32 30 30 37 20 43 72 61 63 6b 2e 7a 69 70 2e 65 78 65 } //1 Windows Vista Ultimate SP3 2007 Crack.zip.exe
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=141
 
}