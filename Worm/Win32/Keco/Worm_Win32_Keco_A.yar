
rule Worm_Win32_Keco_A{
	meta:
		description = "Worm:Win32/Keco.A,SIGNATURE_TYPE_PEHSTR,2b 00 2b 00 09 00 00 "
		
	strings :
		$a_01_0 = {48 45 4c 4f 20 2e 63 6f 6d } //10 HELO .com
		$a_01_1 = {6d 78 31 2e 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //10 mx1.hotmail.com
		$a_01_2 = {43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 62 61 73 65 36 34 } //10 Content-Transfer-Encoding: base64
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_4 = {2d 2d 53 68 75 74 46 61 63 65 2d 2d } //1 --ShutFace--
		$a_01_5 = {2d 2d 56 58 72 75 6c 65 7a 2d 2d } //1 --VXrulez--
		$a_01_6 = {53 74 66 75 40 41 62 75 73 65 2e 63 6f 6d } //1 Stfu@Abuse.com
		$a_01_7 = {2e 64 63 63 20 73 65 6e 64 20 24 6e 69 63 6b } //1 .dcc send $nick
		$a_01_8 = {5c 43 24 5c 41 75 74 6f 45 78 65 63 2e 62 61 74 } //1 \C$\AutoExec.bat
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=43
 
}