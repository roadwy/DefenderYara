
rule Trojan_Win32_Guloader_RPM_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6d 00 6f 00 6e 00 6b 00 62 00 69 00 72 00 64 00 2e 00 52 00 4f 00 53 00 } //1 monkbird.ROS
		$a_01_1 = {50 00 65 00 6e 00 61 00 6c 00 68 00 75 00 73 00 65 00 73 00 2e 00 63 00 65 00 6c 00 } //1 Penalhuses.cel
		$a_01_2 = {6d 00 69 00 64 00 73 00 6f 00 6d 00 6d 00 65 00 72 00 65 00 6e 00 73 00 2e 00 4c 00 65 00 74 00 } //1 midsommerens.Let
		$a_01_3 = {45 00 71 00 75 00 69 00 74 00 69 00 73 00 74 00 2e 00 6c 00 6e 00 6b 00 } //1 Equitist.lnk
		$a_01_4 = {75 00 68 00 65 00 6c 00 64 00 69 00 67 00 76 00 69 00 73 00 65 00 2e 00 41 00 6d 00 65 00 } //1 uheldigvise.Ame
		$a_01_5 = {52 00 61 00 74 00 74 00 65 00 6e 00 65 00 73 00 31 00 33 00 36 00 } //1 Rattenes136
		$a_01_6 = {52 00 69 00 63 00 65 00 62 00 69 00 72 00 64 00 31 00 33 00 38 00 } //1 Ricebird138
		$a_01_7 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 41 00 64 00 64 00 69 00 63 00 74 00 69 00 6f 00 6e 00 73 00 } //1 Software\Addictions
		$a_01_8 = {55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 64 00 65 00 66 00 6c 00 6f 00 77 00 65 00 72 00 69 00 6e 00 67 00 } //1 Uninstall\deflowering
		$a_01_9 = {4b 00 69 00 6c 00 64 00 65 00 73 00 70 00 72 00 6f 00 67 00 65 00 74 00 73 00 5c 00 46 00 6c 00 75 00 76 00 69 00 61 00 74 00 69 00 6f 00 6e 00 33 00 30 00 } //1 Kildesprogets\Fluviation30
		$a_01_10 = {48 00 61 00 75 00 6e 00 63 00 68 00 6c 00 65 00 73 00 73 00 5c 00 67 00 6c 00 61 00 64 00 69 00 61 00 74 00 6f 00 72 00 } //1 Haunchless\gladiator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
rule Trojan_Win32_Guloader_RPM_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPM!MTB,SIGNATURE_TYPE_PEHSTR,1d 00 1d 00 0b 00 00 "
		
	strings :
		$a_01_0 = {41 6e 61 6c 65 72 6f 74 69 6b 6b 65 6e 5c 63 61 79 2e 68 74 6d } //1 Analerotikken\cay.htm
		$a_01_1 = {61 66 66 6c 64 69 67 73 74 5c 66 6c 79 6d 61 6e 2e 67 69 66 } //1 affldigst\flyman.gif
		$a_01_2 = {4b 79 73 74 73 74 72 6b 6e 69 6e 67 65 72 2e 7a 69 70 } //1 Kyststrkninger.zip
		$a_01_3 = {73 6b 6f 6c 65 67 61 61 72 64 65 2e 74 78 74 } //1 skolegaarde.txt
		$a_01_4 = {74 6f 72 75 6c 61 73 2e 7a 69 70 } //10 torulas.zip
		$a_01_5 = {73 6d 75 64 73 65 74 73 5c 64 6f 75 62 6c 65 68 65 61 72 74 65 64 6e 65 73 73 2e 62 69 6e } //1 smudsets\doubleheartedness.bin
		$a_01_6 = {43 61 74 61 6c 65 70 74 69 7a 65 5c 68 6b 73 61 6b 73 65 6e 73 2e 69 6e 69 } //1 Cataleptize\hksaksens.ini
		$a_01_7 = {66 75 72 66 75 72 2e 6c 6e 6b } //1 furfur.lnk
		$a_01_8 = {68 75 6d 64 72 75 6d 6d 69 6e 65 73 73 5c 72 64 76 69 6e 65 73 2e 7a 69 70 } //1 humdrumminess\rdvines.zip
		$a_01_9 = {6f 78 79 64 65 72 69 6e 67 65 72 6e 65 5c 6b 61 6c 6b 65 6e 65 73 5c 53 76 65 64 65 72 65 6d 6d 65 6e 65 73 } //10 oxyderingerne\kalkenes\Svederemmenes
		$a_01_10 = {49 6e 64 74 61 70 70 65 73 2e 62 69 6e } //1 Indtappes.bin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*10+(#a_01_10  & 1)*1) >=29
 
}