
rule Trojan_Win32_RedlineStealer_UA_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.UA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 0c 30 04 31 81 ff 90 01 04 75 90 00 } //10
		$a_03_1 = {b1 6c b0 6d 68 90 01 04 c6 05 90 01 04 69 c6 05 90 01 04 32 c6 05 90 01 04 2e c6 05 90 01 04 67 88 0d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}