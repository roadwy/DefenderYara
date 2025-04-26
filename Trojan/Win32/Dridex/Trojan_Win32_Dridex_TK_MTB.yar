
rule Trojan_Win32_Dridex_TK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.TK!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6c 69 70 75 62 6c 69 73 68 65 64 6b 74 68 65 66 72 6f 6d 33 42 6f 61 72 64 } //1 lipublishedkthefrom3Board
		$a_01_1 = {74 68 65 38 2d 62 69 74 75 4d 6f 6d 7a 43 68 72 6f 6d 65 } //1 the8-bituMomzChrome
		$a_01_2 = {35 74 72 6f 75 62 6c 65 47 6f 6f 67 6c 65 6f 66 74 6f 70 68 61 73 65 74 68 65 72 65 7a 65 6e 74 69 72 65 6c 79 2e 31 30 31 77 69 74 68 } //1 5troubleGoogleoftophasetherezentirely.101with
		$a_01_3 = {45 77 68 69 63 68 77 61 73 6c 66 6f 72 } //1 Ewhichwaslfor
		$a_01_4 = {63 72 61 73 68 33 43 68 72 6f 6d 65 4e 76 65 72 73 69 6f 6e } //1 crash3ChromeNversion
		$a_01_5 = {6c 65 67 65 6e 64 61 66 74 65 72 64 69 72 65 63 74 6c 79 6b 35 6c 6d 6f 6e 6b 65 79 } //1 legendafterdirectlyk5lmonkey
		$a_01_6 = {30 6d 6f 64 65 44 74 68 6f 73 65 74 68 75 6d 62 6e 61 69 6c 73 79 } //1 0modeDthosethumbnailsy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}