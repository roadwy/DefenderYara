
rule Trojan_Win32_Tarcloin_F{
	meta:
		description = "Trojan:Win32/Tarcloin.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 07 2c 46 c0 e3 04 34 07 02 d8 88 5c 24 } //01 00 
		$a_01_1 = {68 75 6d 65 78 2e 70 64 62 00 } //01 00 
		$a_01_2 = {2f 36 35 38 33 35 30 39 36 35 2f } //00 00  /658350965/
	condition:
		any of ($a_*)
 
}