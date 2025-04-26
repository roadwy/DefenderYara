
rule Trojan_Win32_DelayedLogClearing_A{
	meta:
		description = "Trojan:Win32/DelayedLogClearing.A,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 69 00 6e 00 67 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 } //10 ping localhost
		$a_00_1 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 20 00 63 00 6c 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //10 wevtutil cl System
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}