
rule Trojan_BAT_Androm_MBI_MTB{
	meta:
		description = "Trojan:BAT/Androm.MBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 63 d2 48 28 61 9d fe 0c 0a 00 20 03 00 00 00 20 60 d4 d4 43 20 09 d4 d4 43 61 9d fe 0c 0a 00 20 04 00 00 00 20 16 05 36 6b 20 7b 05 36 6b 61 9d fe 0c 0a 00 20 05 00 00 00 } //01 00 
		$a_01_1 = {34 38 35 65 2d 62 64 61 39 2d 39 31 33 39 64 35 64 61 39 33 38 31 } //00 00  485e-bda9-9139d5da9381
	condition:
		any of ($a_*)
 
}