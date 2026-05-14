
rule Trojan_Win64_Vidar_PGAD_MTB{
	meta:
		description = "Trojan:Win64/Vidar.PGAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //1 C:\ProgramData\
		$a_01_1 = {78 4e 5f 5f 42 45 4c 58 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 78 5f 55 54 49 54 55 75 73 } //1 xN__BELX+++++++++++++++++++++++++++++++++++++++++x_UTITUus
		$a_01_2 = {77 6d 70 72 76 6a 72 40 6f 73 6a 78 76 71 6c } //1 wmprvjr@osjxvql
		$a_01_3 = {79 72 4c 4b 41 4a 52 56 79 56 5c 56 51 40 48 } //1 yrLKAJRVyV\VQ@H
		$a_01_4 = {4c 6a 48 5f 42 5d 4e 7b 59 44 48 4e 58 58 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 75 54 53 44 56 70 52 45 58 47 54 61 43 } //1 LjH_B]N{YDHNXX++++++++++++++++++++++++++++++++++++++++++++++uTSDVpREXGTaC
		$a_01_5 = {66 7a 73 61 62 74 67 70 69 78 5c 56 47 5a 46 5a 53 41 69 62 5c 5b 51 5a 42 46 69 76 40 47 47 50 5b 41 63 50 47 46 5c 5a 5b 69 } //1 fzsabtgpix\VGZFZSAib\[QZBFiv@GGP[AcPGF\Z[i
		$a_01_6 = {25 44 4f 57 4e 4c 4f 41 44 53 25 } //1 %DOWNLOADS%
		$a_01_7 = {25 54 45 4d 50 25 } //1 %TEMP%
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}