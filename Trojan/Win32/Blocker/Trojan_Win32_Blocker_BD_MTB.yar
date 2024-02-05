
rule Trojan_Win32_Blocker_BD_MTB{
	meta:
		description = "Trojan:Win32/Blocker.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 1c 18 01 1b 35 00 05 36 00 24 37 00 0f fc 02 19 68 ff 08 68 ff 0d b4 00 38 00 1a 68 ff 80 10 00 1b 1c 00 2a 23 } //02 00 
		$a_01_1 = {1b 29 00 2a 23 2c ff 1b 26 00 2a 46 14 ff 0a 2a 00 08 00 74 0c ff 32 18 00 58 } //00 00 
	condition:
		any of ($a_*)
 
}