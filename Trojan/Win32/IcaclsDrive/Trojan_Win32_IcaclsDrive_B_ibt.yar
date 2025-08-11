
rule Trojan_Win32_IcaclsDrive_B_ibt{
	meta:
		description = "Trojan:Win32/IcaclsDrive.B!ibt,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_02_0 = {26 00 20 00 69 00 63 00 61 00 63 00 6c 00 73 00 [0-60] 2e 00 62 00 69 00 6e 00 20 00 2f 00 67 00 72 00 61 00 6e 00 74 00 20 00 65 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 3a 00 66 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } //20
	condition:
		((#a_02_0  & 1)*20) >=20
 
}