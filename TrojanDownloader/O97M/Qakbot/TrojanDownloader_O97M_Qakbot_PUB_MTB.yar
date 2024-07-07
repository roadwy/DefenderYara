
rule TrojanDownloader_O97M_Qakbot_PUB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PUB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4a 4a 43 43 43 4a 4a } //1 JJCCCJJ
		$a_00_1 = {4a 4a 43 43 42 42 } //1 JJCCBB
		$a_00_2 = {7a 69 70 66 6c 64 72 } //1 zipfldr
		$a_00_3 = {68 74 74 70 73 3a 2f 2f 71 31 73 30 6f 63 69 34 39 6a 6f 2e 78 79 7a 2f 67 75 74 70 61 67 65 2e 70 68 70 } //1 https://q1s0oci49jo.xyz/gutpage.php
		$a_00_4 = {43 3a 5c 72 6f 69 77 6e 73 } //1 C:\roiwns
		$a_00_5 = {5c 64 73 66 73 65 69 2e 65 78 65 } //1 \dsfsei.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}