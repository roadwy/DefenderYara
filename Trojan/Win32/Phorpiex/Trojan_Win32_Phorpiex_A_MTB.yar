
rule Trojan_Win32_Phorpiex_A_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 e8 90 01 04 99 b9 30 75 00 00 f7 f9 81 c2 10 27 00 00 52 8d 95 f0 fb ff ff 52 90 00 } //01 00 
		$a_02_1 = {99 b9 60 ea 00 00 f7 f9 6b d2 90 01 01 81 c2 10 27 00 00 52 ff 15 90 00 } //01 00 
		$a_81_2 = {68 74 74 70 3a 2f 2f 31 38 35 2e 32 31 35 2e 31 31 33 2e 39 33 } //01 00  http://185.215.113.93
		$a_81_3 = {34 77 67 77 34 67 77 34 68 } //01 00  4wgw4gw4h
		$a_81_4 = {61 70 70 64 61 74 61 } //00 00  appdata
	condition:
		any of ($a_*)
 
}