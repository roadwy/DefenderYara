
rule Trojan_BAT_SnakeKeylogger_MS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {13 0c 11 0c 72 46 bd 02 70 28 02 00 00 0a 13 0c 11 0c 72 4e bd 02 70 28 02 00 00 0a 13 0c 11 0c 72 56 bd 02 70 28 02 00 00 0a 13 0c 11 0c 72 5e bd 02 70 28 02 00 00 0a 13 0c 11 0c 72 66 bd 02 70 28 02 00 00 0a 13 0c } //03 00 
		$a_01_1 = {45 00 72 00 62 00 6e 00 4b 00 68 00 4f 00 42 00 69 00 57 00 54 00 53 00 52 00 4b 00 45 00 } //03 00  ErbnKhOBiWTSRKE
		$a_01_2 = {68 00 57 00 51 00 48 00 6c 00 53 00 4f 00 78 00 48 00 51 00 4b 00 61 00 4e 00 44 00 76 00 } //01 00  hWQHlSOxHQKaNDv
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}