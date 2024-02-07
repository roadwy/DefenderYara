
rule Trojan_BAT_SpySnake_MU_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0a 02 8e 69 18 5a 06 8e 69 58 0b 2b 3d 00 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 } //05 00 
		$a_01_1 = {4b 6c 69 65 6e 74 20 64 6f 20 62 6c 69 70 61 } //05 00  Klient do blipa
		$a_01_2 = {42 6c 69 70 46 61 63 65 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  BlipFace.Properties
		$a_01_3 = {68 6f 74 6b 65 79 5f 48 6f 74 6b 65 79 50 72 65 73 73 65 64 } //00 00  hotkey_HotkeyPressed
	condition:
		any of ($a_*)
 
}