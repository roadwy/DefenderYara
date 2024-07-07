
rule Trojan_Win32_RDPCredDumping_C{
	meta:
		description = "Trojan:Win32/RDPCredDumping.C,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //10 tasklist.exe
		$a_00_1 = {2f 00 4d 00 3a 00 72 00 64 00 70 00 63 00 6f 00 72 00 65 00 74 00 73 00 2e 00 64 00 6c 00 6c 00 } //10 /M:rdpcorets.dll
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}