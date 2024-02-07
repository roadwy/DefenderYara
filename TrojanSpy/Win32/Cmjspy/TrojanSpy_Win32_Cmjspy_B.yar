
rule TrojanSpy_Win32_Cmjspy_B{
	meta:
		description = "TrojanSpy:Win32/Cmjspy.B,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {47 65 74 49 70 41 64 64 72 54 61 62 6c 65 } //0a 00  GetIpAddrTable
		$a_00_1 = {50 65 65 6b 4e 61 6d 65 64 50 69 70 65 } //04 00  PeekNamedPipe
		$a_03_2 = {6a 00 57 ff 76 10 e8 90 01 03 ff 83 c4 2c 8d 45 08 6a 00 50 57 ff 76 10 ff 36 ff d3 83 c7 05 90 00 } //05 00 
		$a_02_3 = {68 01 08 00 00 c6 45 fc 03 c7 06 90 01 03 10 89 7e 1c 89 7e 20 89 7e 30 89 7e 18 89 7e 14 c7 46 10 20 4e 00 00 c7 46 0c 00 08 00 00 e8 90 01 03 00 8b 1d 90 01 03 10 c7 04 90 01 04 10 57 6a 01 57 89 46 34 89 7e 58 89 7e 6c 89 7e 70 ff d3 50 89 46 04 ff 15 90 00 } //01 00 
		$a_00_4 = {68 6c 69 63 65 6e 73 65 2e 76 78 64 } //01 00  hlicense.vxd
		$a_00_5 = {73 73 73 64 64 61 33 33 34 33 34 32 2e 76 78 64 } //01 00  sssdda334342.vxd
		$a_00_6 = {68 6c 6f 67 6f 2e 32 74 78 } //01 00  hlogo.2tx
		$a_00_7 = {66 69 6c 65 2e 32 64 69 72 } //01 00  file.2dir
		$a_00_8 = {72 65 67 2e 32 67 65 72 } //01 00  reg.2ger
		$a_00_9 = {63 6d 64 2e 65 78 65 00 63 6f 6d 6d 61 6e 64 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}