
rule Trojan_Win32_Dreammon_C{
	meta:
		description = "Trojan:Win32/Dreammon.C,SIGNATURE_TYPE_PEHSTR,16 00 15 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {64 72 65 61 6d 2f 64 72 65 61 6d 2e 70 68 70 } //0a 00  dream/dream.php
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 73 2f 25 73 3f 74 79 70 65 3d 65 78 65 26 63 6f 6f 6b 69 65 3d } //0a 00  http://%s/%s?type=exe&cookie=
		$a_01_2 = {44 72 65 61 6d 4f 6e 63 65 46 75 6e 44 6f 77 6e 50 61 74 68 } //01 00  DreamOnceFunDownPath
		$a_01_3 = {69 6e 69 2e 6f 66 66 69 63 65 73 75 70 64 61 74 65 2e 6e 65 74 } //01 00  ini.officesupdate.net
		$a_01_4 = {69 6e 69 2e 6f 66 66 69 63 65 32 30 30 35 75 70 64 61 74 65 73 2e 6e 65 74 } //01 00  ini.office2005updates.net
		$a_01_5 = {69 6e 69 2e 6d 73 6e 6d 65 73 73 65 6e 67 65 72 75 70 64 61 74 65 2e 6e 65 74 } //00 00  ini.msnmessengerupdate.net
	condition:
		any of ($a_*)
 
}