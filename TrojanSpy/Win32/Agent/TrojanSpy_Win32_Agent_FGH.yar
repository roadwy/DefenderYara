
rule TrojanSpy_Win32_Agent_FGH{
	meta:
		description = "TrojanSpy:Win32/Agent.FGH,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_01_0 = {26 74 79 74 75 6c 3d 54 69 62 69 73 73 61 2e 63 6f 6d 26 74 72 65 73 63 3d 4e 61 7a 77 61 25 32 30 6b 6f 6e 74 61 3a } //1 &tytul=Tibissa.com&tresc=Nazwa%20konta:
		$a_01_1 = {44 6f 63 6b 53 69 74 65 } //1 DockSite
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } //1 Software\Microsoft\Windows\CurrentVersion\Policies\System
		$a_01_3 = {2e 67 69 66 25 33 45 20 3c 62 72 3e 20 2e 2e 2e 2e 2e 2e 2e 2e 20 } //1 .gif%3E <br> ........ 
		$a_01_4 = {5c 6f 63 73 64 65 62 75 67 2e 74 78 74 } //1 \ocsdebug.txt
		$a_01_5 = {54 69 62 69 61 20 2d 20 46 72 65 65 20 4d 75 6c 74 69 70 6c 61 79 65 72 20 4f 6e 6c 69 6e 65 20 52 6f 6c 65 20 50 6c 61 79 69 6e 67 20 47 61 6d 65 20 2d 20 41 63 63 6f 75 6e 74 } //1 Tibia - Free Multiplayer Online Role Playing Game - Account
		$a_01_6 = {3e 43 68 61 72 61 63 74 65 72 25 32 30 6f 6e 25 32 30 74 68 65 25 32 30 6d 61 70 3c 61 3e 26 6f 64 3d } //1 >Character%20on%20the%20map<a>&od=
		$a_01_7 = {3e 5a 6f 62 61 63 7a 25 32 30 70 6f 73 74 61 63 25 32 30 6e 61 25 32 30 54 69 62 69 61 2e 63 6f 6d 3c 61 3e 2b 3c 62 72 3e 2b 3c 61 25 32 30 68 72 65 66 3d 68 74 74 70 73 3a 2f 2f 73 65 63 75 72 65 2e 74 69 62 69 61 2e 63 6f 6d 2f 61 63 63 6f 75 6e 74 2f 3f 73 75 62 74 6f 70 69 63 3d 61 63 63 6f 75 6e 74 6d 61 6e 61 67 65 6d 65 6e 74 3e 5a 61 6c 6f 67 75 6a 25 32 30 73 69 65 25 32 30 6e 61 25 32 30 54 69 62 69 61 2e 63 6f 6d 3c 61 3e 2b 3c 62 72 3e 2b 3c 61 25 32 30 68 72 65 66 3d 68 74 74 70 3a 2f 2f 74 69 62 69 61 2e 70 6c 2f 65 61 72 74 68 2e 70 68 70 3f 78 3d } //1 >Zobacz%20postac%20na%20Tibia.com<a>+<br>+<a%20href=https://secure.tibia.com/account/?subtopic=accountmanagement>Zaloguj%20sie%20na%20Tibia.com<a>+<br>+<a%20href=http://tibia.pl/earth.php?x=
		$a_01_8 = {3c 62 72 3e 48 61 73 6c 6f 3a } //1 <br>Haslo:
		$a_01_9 = {3c 62 72 3e 57 6f 72 6c 64 3a } //1 <br>World:
		$a_01_10 = {26 74 79 74 75 6c 3d 54 69 62 69 73 73 61 2e 63 6f 6d 26 74 72 65 73 63 3d 41 63 63 6f 75 6e 74 25 32 30 6e 61 6d 65 3a } //1 &tytul=Tibissa.com&tresc=Account%20name:
		$a_01_11 = {3e 50 6f 6c 6f 7a 65 6e 69 65 25 32 30 70 6f 73 74 61 63 69 25 32 30 6e 61 25 32 30 6d 61 70 69 65 3c 61 3e 26 6f 64 3d } //1 >Polozenie%20postaci%20na%20mapie<a>&od=
		$a_01_12 = {3c 62 72 3e 3c 61 25 32 30 68 72 65 66 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 74 69 62 69 61 2e 63 6f 6d 2f 63 6f 6d 6d 75 6e 69 74 79 2f 3f 73 75 62 74 6f 70 69 63 3d 63 68 61 72 61 63 74 65 72 73 25 32 36 6e 61 6d 65 3d } //1 <br><a%20href=http://www.tibia.com/community/?subtopic=characters%26name=
		$a_01_13 = {2e 67 69 66 25 33 45 3c 62 72 3e 49 64 65 6e 74 79 66 69 6b 61 74 6f 72 3a } //1 .gif%3E<br>Identyfikator:
		$a_01_14 = {76 63 6c 74 65 73 74 33 2e 64 6c 6c } //1 vcltest3.dll
		$a_01_15 = {4c 69 73 74 41 63 74 6e 73 } //1 ListActns
		$a_01_16 = {3e 49 6e 66 6f 72 6d 61 74 69 6f 6e 73 25 32 30 66 72 6f 6d 25 32 30 54 69 62 69 61 2e 63 6f 6d 3c 61 3e 2b 3c 62 72 3e 2b 3c 61 25 32 30 68 72 65 66 3d 68 74 74 70 73 3a 2f 2f 73 65 63 75 72 65 2e 74 69 62 69 61 2e 63 6f 6d 2f 61 63 63 6f 75 6e 74 2f 3f 73 75 62 74 6f 70 69 63 3d 61 63 63 6f 75 6e 74 6d 61 6e 61 67 65 6d 65 6e 74 3e 4c 6f 67 69 6e 25 32 30 74 6f 25 32 30 54 69 62 69 61 2e 63 6f 6d 3c 61 3e 2b 3c 62 72 3e 2b 3c 61 25 32 30 68 72 65 66 3d 68 74 74 70 3a 2f 2f 74 69 62 69 61 2e 70 6c 2f 65 61 72 74 68 2e 70 68 70 3f 78 3d } //1 >Informations%20from%20Tibia.com<a>+<br>+<a%20href=https://secure.tibia.com/account/?subtopic=accountmanagement>Login%20to%20Tibia.com<a>+<br>+<a%20href=http://tibia.pl/earth.php?x=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=17
 
}