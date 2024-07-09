
rule BrowserModifier_Win32_Startpage{
	meta:
		description = "BrowserModifier:Win32/Startpage,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {86 51 e9 b6 85 3c 5b 5f 33 c9 59 bd 5f 28 73 99 4e 25 64 6e 61 24 a8 61 75 3f aa ee 34 } //2
		$a_01_1 = {8b 4c 24 08 8a 01 56 2c 39 57 8b 7c 24 0c 0f b6 f0 56 8d 41 01 50 57 6a 01 51 e8 27 ff ff ff 83 c4 14 c6 44 3e ff 00 8b c7 5f 5e c3 } //2
		$a_01_2 = {2c 44 6c 6c 49 6e 73 74 61 6c 6c } //2 ,DllInstall
		$a_02_3 = {73 65 61 72 63 68 2d 70 69 6e 28 [0-04] 29 2e 64 6c 6c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_02_3  & 1)*2) >=6
 
}
rule BrowserModifier_Win32_Startpage_2{
	meta:
		description = "BrowserModifier:Win32/Startpage,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {30 30 30 30 30 30 30 32 2d 30 30 30 31 2d 30 30 30 32 2d 30 30 30 30 2d 30 30 30 30 46 38 46 33 35 35 37 42 7d } //2 00000002-0001-0002-0000-0000F8F3557B}
		$a_01_1 = {50 52 4f 54 4f 43 4f 4c 53 5c 46 69 6c 74 65 72 5c 74 65 78 74 2f 68 74 6d 6c } //2 PROTOCOLS\Filter\text/html
		$a_01_2 = {20 20 61 6c 65 72 74 28 22 50 6c 65 61 73 65 20 73 70 65 63 69 66 79 20 73 6f 6d 65 74 68 69 6e 67 20 74 6f 20 73 65 61 72 63 68 20 66 6f 72 21 22 29 3b } //5   alert("Please specify something to search for!");
		$a_01_3 = {66 75 6e 63 74 69 6f 6e 20 67 6f 28 74 65 78 74 29 20 7b 20 66 6f 72 6d 57 65 62 2e 77 77 2e 76 61 6c 75 65 3d 74 65 78 74 3b } //2 function go(text) { formWeb.ww.value=text;
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*5+(#a_01_3  & 1)*2) >=11
 
}
rule BrowserModifier_Win32_Startpage_3{
	meta:
		description = "BrowserModifier:Win32/Startpage,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 68 6f 6d 65 70 61 67 65 22 2c 20 22 25 75 72 6c 25 22 29 3b 20 3e 3e 20 22 25 41 50 50 44 41 54 41 25 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c } //1 .homepage", "%url%"); >> "%APPDATA%\Mozilla\Firefox\
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 55 52 4c 53 65 74 74 65 72 2e 62 61 74 } //1 cmd.exe /c del URLSetter.bat
		$a_01_2 = {65 63 68 6f 20 22 53 74 61 72 74 20 50 61 67 65 22 3d 22 25 75 72 6c 25 22 20 3e 3e 20 49 45 5f 48 6f 6d 65 50 61 67 65 5f 52 65 73 65 74 2e 72 65 67 } //1 echo "Start Page"="%url%" >> IE_HomePage_Reset.reg
		$a_01_3 = {52 45 47 45 44 49 54 20 2f 53 20 49 45 5f 48 6f 6d 65 50 61 67 65 5f 72 65 73 65 74 2e 72 65 67 20 } //1 REGEDIT /S IE_HomePage_reset.reg 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}