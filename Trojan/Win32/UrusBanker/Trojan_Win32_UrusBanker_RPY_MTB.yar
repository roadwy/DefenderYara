
rule Trojan_Win32_UrusBanker_RPY_MTB{
	meta:
		description = "Trojan:Win32/UrusBanker.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 63 00 70 00 75 00 64 00 6c 00 6e 00 2e 00 63 00 6f 00 6d 00 } //01 00  download.cpudln.com
		$a_01_1 = {31 00 31 00 37 00 2e 00 37 00 39 00 2e 00 38 00 30 00 2e 00 31 00 36 00 39 00 } //01 00  117.79.80.169
		$a_01_2 = {50 00 32 00 50 00 2e 00 76 00 62 00 70 00 } //01 00  P2P.vbp
		$a_01_3 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6c 00 6f 00 63 00 6b 00 2e 00 6c 00 6f 00 67 00 } //01 00  windows\lock.log
		$a_01_4 = {65 70 6c 64 72 69 76 65 2e 64 6c 6c } //01 00  epldrive.dll
		$a_01_5 = {75 72 6c 6d 6f 6e } //01 00  urlmon
		$a_01_6 = {44 6f 77 6e 55 72 6c } //01 00  DownUrl
		$a_01_7 = {6d 6f 64 53 6f 63 6b 65 74 4d 61 73 74 65 72 } //00 00  modSocketMaster
	condition:
		any of ($a_*)
 
}