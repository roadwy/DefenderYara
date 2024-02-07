
rule PWS_Win32_Savnut_G{
	meta:
		description = "PWS:Win32/Savnut.G,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 0d 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 7d dc 66 c7 07 5c 2a 66 af 8a 01 aa 41 84 c0 75 f8 } //04 00 
		$a_01_1 = {8b 7d f0 b8 47 00 00 00 ba 6f 6f 67 6c b9 fc 0f 00 00 8b c0 f2 ae e3 04 39 17 75 f6 51 } //03 00 
		$a_01_2 = {81 39 68 74 74 70 75 03 83 c1 07 51 e8 } //03 00 
		$a_01_3 = {74 11 8b 55 08 c6 02 e9 8b 45 0c 2b c2 83 e8 05 89 42 01 } //01 00 
		$a_01_4 = {26 76 65 72 73 69 6f 6e 32 3d 35 38 36 26 76 65 6e 64 6f 72 3d 4f 6c 64 } //01 00  &version2=586&vendor=Old
		$a_01_5 = {5c 75 72 68 74 70 73 2e 74 6d 70 } //01 00  \urhtps.tmp
		$a_01_6 = {25 73 6e 65 74 62 61 6e 6b 65 5f 25 73 5f 25 73 } //01 00  %snetbanke_%s_%s
		$a_01_7 = {5c 73 72 76 62 6c 63 6b 32 2e 74 6d 70 } //01 00  \srvblck2.tmp
		$a_01_8 = {62 61 6e 6b 63 68 61 6e 67 65 68 6f 73 74 } //01 00  bankchangehost
		$a_01_9 = {25 73 5c 25 73 5f 25 30 38 64 2e 6d 70 73 74 } //01 00  %s\%s_%08d.mpst
		$a_01_10 = {25 73 5c 25 73 5f 25 30 38 64 2e 6c 6b 65 79 } //01 00  %s\%s_%08d.lkey
		$a_01_11 = {78 6f 7a 5f 63 6f 6f 6b 69 65 73 20 } //02 00  xoz_cookies 
		$a_01_12 = {c7 07 55 53 46 3d af 33 c0 } //00 00 
	condition:
		any of ($a_*)
 
}