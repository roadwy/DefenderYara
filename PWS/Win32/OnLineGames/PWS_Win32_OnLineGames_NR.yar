
rule PWS_Win32_OnLineGames_NR{
	meta:
		description = "PWS:Win32/OnLineGames.NR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 3d 50 41 53 53 57 44 } //1 svc=PASSWD
		$a_01_1 = {6c 2e 66 6f 72 63 65 2e 76 61 6c 75 65 3d 64 2b 22 63 62 63 62 22 2b 70 3b 2f 2a } //1 l.force.value=d+"cbcb"+p;/*
		$a_01_2 = {5c 72 65 73 5c 50 43 4f 54 50 2e 6f 6b 66 } //1 \res\PCOTP.okf
		$a_01_3 = {47 61 6d 65 47 75 61 72 64 2e 64 65 73 } //1 GameGuard.des
		$a_01_4 = {73 74 72 4c 65 66 74 49 44 2b 3d 22 3b 70 61 74 68 3d 2f 3b 64 6f 6d 61 69 6e 3d 6e 65 78 6f 6e 2e 63 6f 6d 3b 22 3b } //1 strLeftID+=";path=/;domain=nexon.com;";
		$a_01_5 = {70 61 79 70 61 6c 2e } //1 paypal.
		$a_01_6 = {70 61 67 65 5f 67 61 6d 65 69 64 3d } //1 page_gameid=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}