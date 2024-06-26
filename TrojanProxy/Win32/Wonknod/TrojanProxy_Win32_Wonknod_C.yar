
rule TrojanProxy_Win32_Wonknod_C{
	meta:
		description = "TrojanProxy:Win32/Wonknod.C,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 0a 00 00 32 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 c7 05 90 01 04 3a 2f 2f 90 01 01 c7 05 90 00 } //32 00 
		$a_03_1 = {25 73 5c 25 c7 05 90 01 04 30 32 64 25 c7 05 90 00 } //01 00 
		$a_00_2 = {78 36 34 2e 7a 69 70 } //01 00  x64.zip
		$a_00_3 = {78 33 32 2e 7a 69 70 } //01 00  x32.zip
		$a_00_4 = {2c 61 64 6d 69 6e 3d } //01 00  ,admin=
		$a_00_5 = {2c 67 75 69 64 3d } //01 00  ,guid=
		$a_00_6 = {5c 00 42 00 79 00 70 00 61 00 73 00 73 00 } //01 00  \Bypass
		$a_00_7 = {5c 00 67 00 75 00 69 00 64 00 2e 00 6c 00 6f 00 67 00 } //01 00  \guid.log
		$a_00_8 = {63 74 2e 7a 69 70 } //01 00  ct.zip
		$a_00_9 = {63 74 2e 65 78 65 } //00 00  ct.exe
	condition:
		any of ($a_*)
 
}