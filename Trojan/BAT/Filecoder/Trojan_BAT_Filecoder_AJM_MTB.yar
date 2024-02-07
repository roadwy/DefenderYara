
rule Trojan_BAT_Filecoder_AJM_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.AJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 5b 00 78 00 6d 00 72 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 5d 00 } //01 00  .[xmrlocker]
		$a_01_1 = {72 00 65 00 61 00 64 00 6d 00 65 00 28 00 68 00 6f 00 77 00 74 00 6f 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 29 00 2e 00 74 00 78 00 74 00 } //01 00  readme(howtodecrypt).txt
		$a_01_2 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 6c 00 6f 00 63 00 6b 00 78 00 6d 00 72 00 40 00 64 00 61 00 75 00 6d 00 2e 00 6e 00 65 00 74 00 } //01 00  All your files are encrypted by lockxmr@daum.net
		$a_01_3 = {6c 00 6f 00 63 00 6b 00 78 00 6d 00 72 00 40 00 61 00 69 00 72 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 63 00 } //01 00  lockxmr@airmail.cc
		$a_01_4 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  vssadmin.exe
		$a_81_5 = {41 6c 70 68 61 6c 65 6f 6e 69 73 2e 57 69 6e 33 32 2e 4e 65 74 77 6f 72 6b } //00 00  Alphaleonis.Win32.Network
	condition:
		any of ($a_*)
 
}