
rule Trojan_Win32_Flystudio_RF_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 37 46 43 31 41 45 34 35 43 35 43 34 37 35 38 41 46 30 33 45 46 31 39 46 31 38 41 33 39 35 44 } //01 00  F7FC1AE45C5C4758AF03EF19F18A395D
		$a_81_1 = {66 75 63 6b 2e 69 6e 69 } //01 00  fuck.ini
		$a_81_2 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  http\shell\open\command
		$a_81_3 = {68 74 74 70 73 3a 2f 2f 68 61 6f 2e 33 36 30 2e 63 6e 2f } //01 00  https://hao.360.cn/
		$a_81_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 32 33 34 35 2e 63 6f 6d 2f } //01 00  http://www.2345.com/
		$a_81_5 = {74 61 6f 62 61 6f 2e 63 6f 6d } //00 00  taobao.com
	condition:
		any of ($a_*)
 
}