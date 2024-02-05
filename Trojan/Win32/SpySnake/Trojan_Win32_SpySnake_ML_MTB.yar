
rule Trojan_Win32_SpySnake_ML_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {33 ff 8d 85 e4 fe ff ff 57 68 80 00 00 00 6a 03 57 6a 01 68 00 00 00 80 50 ff 15 } //0a 00 
		$a_03_1 = {8b f0 57 56 ff 15 90 01 04 6a 40 8b d8 68 00 30 00 00 53 57 89 5d fc ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}