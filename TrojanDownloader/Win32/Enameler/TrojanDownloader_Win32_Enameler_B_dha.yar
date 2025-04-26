
rule TrojanDownloader_Win32_Enameler_B_dha{
	meta:
		description = "TrojanDownloader:Win32/Enameler.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 73 2e 65 78 65 } //1 svchosts.exe
		$a_01_1 = {2f 66 69 6c 65 73 2f 69 6e 64 65 78 2e 70 68 70 3f } //1 /files/index.php?
		$a_01_2 = {45 4e 41 4d 45 4c 49 42 } //1 ENAMELIB
		$a_01_3 = {67 6e 61 6d 65 } //1 gname
		$a_01_4 = {6d 73 64 74 63 70 77 65 2e 64 61 74 } //1 msdtcpwe.dat
		$a_01_5 = {68 74 6d 6c 3c 27 27 4b 28 2a } //1 html<''K(*
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}