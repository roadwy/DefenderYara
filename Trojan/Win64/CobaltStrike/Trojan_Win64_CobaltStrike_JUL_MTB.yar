
rule Trojan_Win64_CobaltStrike_JUL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 48 8b 05 72 db 04 00 31 0d 2c db 04 00 31 14 03 48 83 c3 04 8b 15 3b db 04 00 8b 0d bd db 04 00 2b 0d db da 04 00 8b 05 90 01 04 83 c0 d4 03 c8 8b 05 90 01 04 89 0d 64 db 04 00 05 90 00 } //01 00 
		$a_03_1 = {8b ca 2b 0d 03 db 04 00 03 c8 8b 05 90 01 04 89 0d c5 da 04 00 8d 8a 66 17 fa ff 01 0d 8d da 04 00 48 8b 0d 6e da 04 00 2b 81 ec 00 00 00 35 f1 95 e4 ff 29 81 d4 00 00 00 8b 0d 93 da 04 00 48 8b 15 50 da 04 00 81 c1 2b 24 fd ff 03 0d 1c db 04 00 01 4a 08 8b 15 8b da 04 00 03 15 dd da 04 00 89 15 90 01 04 48 81 fb 80 03 00 00 0f 8c 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}