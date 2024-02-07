
rule Trojan_Win32_Razy_T_MSR{
	meta:
		description = "Trojan:Win32/Razy.T!MSR,SIGNATURE_TYPE_PEHSTR_EXT,2f 00 2f 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 78 00 7a 00 73 00 69 00 74 00 65 00 2e 00 63 00 68 00 75 00 6a 00 7a 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 6f 00 66 00 74 00 2f 00 61 00 64 00 2e 00 68 00 74 00 6d 00 6c 00 } //0a 00  http://xzsite.chujz.com/soft/ad.html
		$a_01_1 = {5c 00 65 00 78 00 74 00 72 00 61 00 2e 00 7a 00 69 00 70 00 } //0a 00  \extra.zip
		$a_01_2 = {71 68 61 63 74 69 76 65 64 65 66 65 6e 73 65 } //0a 00  qhactivedefense
		$a_01_3 = {33 36 30 74 6f 74 61 6c 73 65 63 75 72 69 74 79 } //01 00  360totalsecurity
		$a_01_4 = {65 74 68 65 72 65 61 6c } //01 00  ethereal
		$a_01_5 = {68 74 74 70 61 6e 61 6c 79 7a 65 72 } //01 00  httpanalyzer
		$a_01_6 = {69 64 61 20 70 72 6f } //01 00  ida pro
		$a_01_7 = {6f 6c 6c 79 64 62 67 } //01 00  ollydbg
		$a_01_8 = {76 62 6f 78 73 65 72 76 69 63 65 } //01 00  vboxservice
		$a_01_9 = {76 6d 74 6f 6f 6c } //01 00  vmtool
		$a_01_10 = {77 69 72 65 73 68 61 72 6b } //00 00  wireshark
	condition:
		any of ($a_*)
 
}