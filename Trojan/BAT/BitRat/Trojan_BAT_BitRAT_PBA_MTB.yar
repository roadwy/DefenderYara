
rule Trojan_BAT_BitRAT_PBA_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 38 8b d8 ff 15 8d 90 01 03 66 89 b7 fe 07 00 00 85 db 90 00 } //01 00 
		$a_03_1 = {44 89 6c 24 30 c7 44 24 3c 02 00 00 00 4c 89 7c 24 20 ff 15 90 01 03 00 41 8b cd e8 dd 90 00 } //01 00 
		$a_03_2 = {8d 55 66 ff 15 90 01 03 00 48 89 05 db 2e 02 00 90 00 } //01 00 
		$a_03_3 = {8d 0d 8a 59 02 00 e8 90 01 03 00 ff 15 87 50 00 00 48 8d 1d 90 00 } //01 00 
		$a_03_4 = {48 ff 25 42 17 00 00 cc cc 48 89 5c 24 08 57 48 83 ec 30 33 db 4c 8d 4c 24 58 48 89 5c 24 20 41 8b f8 ff 15 90 01 03 00 85 c0 74 0b 3b 7c 24 58 75 05 bb 01 00 00 00 8b c3 48 8b 5c 24 40 48 83 c4 30 5f c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}