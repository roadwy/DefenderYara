
rule Trojan_Win32_Agent_NAN{
	meta:
		description = "Trojan:Win32/Agent.NAN,SIGNATURE_TYPE_PEHSTR,14 00 14 00 0e 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 6c 79 73 65 78 2e } //5 onlysex.
		$a_01_1 = {5c 6d 73 76 73 72 65 73 2e 64 6c 6c } //2 \msvsres.dll
		$a_01_2 = {77 77 77 2e 6d 73 6e 70 72 6f 74 65 63 74 69 6f 6e 2e 63 6f 6d } //2 www.msnprotection.com
		$a_01_3 = {77 77 77 2e 6d 73 6e 68 65 6c 70 65 72 2e 6e 65 74 } //2 www.msnhelper.net
		$a_01_4 = {2f 66 6c 75 73 68 64 6e 73 } //2 /flushdns
		$a_01_5 = {2f 72 65 67 69 73 74 65 72 64 6e 73 } //2 /registerdns
		$a_01_6 = {77 77 77 2e 70 63 73 70 79 72 65 6d 6f 76 65 72 2e 63 6f 6d 2f 68 65 6c 70 2f 72 65 66 2e 70 68 70 } //2 www.pcspyremover.com/help/ref.php
		$a_01_7 = {77 77 77 2e 6e 6f 6d 6f 72 65 70 63 73 70 69 65 73 2e 63 6f 6d 2f 68 65 6c 70 2f 72 65 66 2e 70 68 70 } //2 www.nomorepcspies.com/help/ref.php
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 74 74 69 6e 67 73 } //2 Software\Microsoft\Internet Explorer\Settings
		$a_01_9 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 62 72 6f 77 73 65 72 20 68 65 6c 70 65 72 20 6f 62 6a 65 63 74 73 } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\browser helper objects
		$a_01_10 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //2 software\microsoft\windows\currentversion\run
		$a_01_11 = {68 61 70 70 79 2d 6d 6f 76 69 65 73 2e 63 6f 6d } //1 happy-movies.com
		$a_01_12 = {68 61 72 64 6d 6f 76 69 65 73 2e 6e 65 74 } //1 hardmovies.net
		$a_01_13 = {62 69 72 64 6d 6f 76 69 65 73 2e 63 6f 6d } //1 birdmovies.com
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=20
 
}