
rule Trojan_BAT_SnakeKeylogger_NED_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 78 20 48 4d 41 20 56 50 4e } //01 00  Privax HMA VPN
		$a_01_1 = {62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 } //01 00  b77a5c561934e089
		$a_01_2 = {70 4f 4d 4d 51 51 51 } //01 00  pOMMQQQ
		$a_01_3 = {6a 44 51 64 71 71 } //01 00  jDQdqq
		$a_01_4 = {45 2a 2b 2b 69 6d 6d 65 72 72 } //00 00  E*++immerr
	condition:
		any of ($a_*)
 
}