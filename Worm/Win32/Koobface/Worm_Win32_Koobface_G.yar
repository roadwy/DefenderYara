
rule Worm_Win32_Koobface_G{
	meta:
		description = "Worm:Win32/Koobface.G,SIGNATURE_TYPE_PEHSTR_EXT,35 00 35 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6d 79 73 70 61 63 65 2e 63 6f 6d } //0a 00  myspace.com
		$a_00_1 = {64 65 6c 20 22 25 73 22 } //0a 00  del "%s"
		$a_00_2 = {25 73 20 22 25 73 22 20 67 6f 74 6f } //0a 00  %s "%s" goto
		$a_00_3 = {25 73 5c 65 78 5f 25 64 2e 65 78 65 } //0a 00  %s\ex_%d.exe
		$a_00_4 = {55 73 65 25 73 69 6c 6c 25 73 6e 64 25 73 76 } //01 00  Use%sill%snd%sv
		$a_00_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 25 73 2f 4d 79 46 72 69 65 6e 64 73 2e 6a 73 70 } //01 00  http://www.%s/MyFriends.jsp
		$a_02_6 = {72 65 67 65 64 69 74 20 2f 73 20 63 3a 5c 90 02 02 2e 72 65 67 90 00 } //02 00 
		$a_00_7 = {6e 69 63 6b 3d 25 73 26 6c 6f 67 69 6e 3d 25 73 26 73 75 63 63 65 73 73 3d 25 64 26 66 72 69 65 6e 64 73 3d 25 64 26 63 61 70 74 63 68 61 3d 25 64 } //01 00  nick=%s&login=%s&success=%d&friends=%d&captcha=%d
		$a_00_8 = {55 72 6c 45 73 63 61 70 65 41 } //01 00  UrlEscapeA
		$a_00_9 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //00 00  InternetGetConnectedState
	condition:
		any of ($a_*)
 
}