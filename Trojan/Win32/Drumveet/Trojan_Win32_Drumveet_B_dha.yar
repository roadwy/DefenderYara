
rule Trojan_Win32_Drumveet_B_dha{
	meta:
		description = "Trojan:Win32/Drumveet.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 5c 63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 } //1 taskkill /F /IM \cookies.sqlite
		$a_01_1 = {2f 75 70 6c 6f 61 64 2e 70 68 70 } //1 /upload.php
		$a_01_2 = {2f 6f 64 63 6f 6d 6d 61 6e 64 2e 70 68 70 3f 63 6c 69 65 5c 63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 } //1 /odcommand.php?clie\cookies.sqlite
		$a_01_3 = {65 63 68 6f 20 73 79 73 74 65 6d 69 6e 66 6f 3a 73 79 73 74 65 6d 69 6e 66 6f 20 3e 3e 31 } //1 echo systeminfo:systeminfo >>1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}