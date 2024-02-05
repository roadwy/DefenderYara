
rule TrojanDropper_Win32_Cutwail_H{
	meta:
		description = "TrojanDropper:Win32/Cutwail.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {c3 8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc ff 15 90 01 02 40 00 8b 45 08 90 02 03 90 03 08 06 8d 8e b0 00 00 00 89 01 89 86 b0 00 00 00 56 90 00 } //01 00 
		$a_02_1 = {c3 8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc 8d 05 90 01 02 40 00 50 6a 00 e8 90 01 02 ff ff ff 15 90 01 02 40 00 8b 45 0c 8d 0e 81 c1 b0 00 00 00 89 01 56 90 00 } //01 00 
		$a_02_2 = {c3 8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc ff 15 90 01 02 40 00 8b 45 0c 8d 0e 81 c1 b0 00 00 00 89 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}