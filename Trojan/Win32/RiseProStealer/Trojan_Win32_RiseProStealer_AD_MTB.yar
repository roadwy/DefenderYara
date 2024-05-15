
rule Trojan_Win32_RiseProStealer_AD_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 01 8b 0c 24 83 c4 04 52 50 } //01 00 
		$a_01_1 = {01 d0 01 18 58 5a 55 52 } //01 00 
		$a_01_2 = {89 14 24 ba 83 41 d9 71 c1 e2 03 c1 ea 02 81 c2 fb 7c 4d dc 29 d1 5a } //01 00 
		$a_81_3 = {41 79 33 49 6e 66 6f 2e 65 78 65 } //01 00  Ay3Info.exe
		$a_01_4 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } //01 00  %userappdata%\RestartApp.exe
		$a_01_5 = {5c 2e 5c 47 6c 6f 62 61 6c 5c 6f 72 65 61 6e 73 33 32 } //00 00  \.\Global\oreans32
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RiseProStealer_AD_MTB_2{
	meta:
		description = "Trojan:Win32/RiseProStealer.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 33 36 34 38 64 38 39 2d 62 30 30 63 2d 34 37 65 66 2d 39 31 30 30 2d 31 63 35 35 35 37 37 36 38 63 33 61 } //01 00  33648d89-b00c-47ef-9100-1c5557768c3a
		$a_01_1 = {50 6f 6c 79 6d 6f 64 58 54 } //01 00  PolymodXT
		$a_81_2 = {6e 69 74 4f 4b 6c 70 36 61 6e 34 72 54 69 72 71 6d 6b 75 36 33 69 74 4f 4b 75 71 61 53 37 72 65 4b 30 34 72 79 36 76 61 33 69 74 4f 4b 38 75 72 32 74 } //01 00  nitOKlp6an4rTirqmku63itOKuqaS7reK04ry6va3itOK8ur2t
		$a_81_3 = {66 61 69 6c 65 64 20 72 65 61 64 70 61 63 6b 65 74 } //01 00  failed readpacket
		$a_81_4 = {66 61 69 65 6c 64 20 73 65 6e 64 70 61 63 6b 65 74 } //00 00  faield sendpacket
	condition:
		any of ($a_*)
 
}