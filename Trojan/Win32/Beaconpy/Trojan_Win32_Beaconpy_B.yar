
rule Trojan_Win32_Beaconpy_B{
	meta:
		description = "Trojan:Win32/Beaconpy.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {75 00 72 00 6c 00 6c 00 69 00 62 00 2e 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 [0-10] 65 00 78 00 65 00 63 00 28 00 } //3
		$a_00_1 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 70 00 79 00 74 00 68 00 6f 00 6e 00 2d 00 70 00 6f 00 65 00 74 00 72 00 79 00 2e 00 6f 00 72 00 67 00 } //-100 install.python-poetry.org
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*-100) >=3
 
}