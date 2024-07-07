
rule Trojan_Win32_Beaconpy_B{
	meta:
		description = "Trojan:Win32/Beaconpy.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {75 00 72 00 6c 00 6c 00 69 00 62 00 2e 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 90 02 10 65 00 78 00 65 00 63 00 28 00 90 00 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}