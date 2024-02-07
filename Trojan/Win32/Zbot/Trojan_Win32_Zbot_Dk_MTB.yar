
rule Trojan_Win32_Zbot_Dk_MTB{
	meta:
		description = "Trojan:Win32/Zbot.Dk!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 54 45 4d 50 5c 6c 63 62 6f 63 2e 65 78 65 } //01 00  C:\TEMP\lcboc.exe
		$a_01_1 = {68 69 74 65 63 68 63 65 6c 6c 2e 63 61 } //01 00  hitechcell.ca
		$a_01_2 = {6b 65 6c 6f 77 6e 61 74 6f 77 6e 68 6f 6d 65 73 2e 63 6f 6d } //01 00  kelownatownhomes.com
		$a_01_3 = {6e 75 6f 62 66 2e 65 78 65 } //01 00  nuobf.exe
		$a_01_4 = {68 70 79 72 7a 2e 65 78 65 } //01 00  hpyrz.exe
		$a_01_5 = {79 71 67 6a 63 2e 65 78 65 } //01 00  yqgjc.exe
		$a_01_6 = {74 68 65 73 75 6e 64 61 6e 63 65 73 63 68 6f 6f 6c 2e 63 6f 6d } //00 00  thesundanceschool.com
	condition:
		any of ($a_*)
 
}