
rule Trojan_Win64_ClipBanker_F_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 89 85 a0 04 00 00 c7 85 84 04 00 00 00 00 00 00 48 8d 0d 28 6b 1c 00 e8 e8 57 fc ff 48 8d 15 39 6f 15 00 48 8d 4d 08 e8 c5 24 fc ff 90 48 8d 15 58 6f 15 00 48 8d 4d 48 e8 b4 24 fc ff 90 ba 58 00 00 00 48 8d 8d 90 00 00 00 e8 c8 49 fc ff 41 b8 01 00 00 00 48 8d 15 68 6f 15 00 48 8d 8d 90 00 00 00 e8 ed 29 fc ff 90 ba 58 00 00 00 48 8d 8d 10 01 00 00 e8 9d 49 fc ff 41 b8 01 00 00 00 48 8d 15 5d 6f 15 00 48 8d 8d 10 01 00 00 e8 c2 29 fc ff } //02 00 
		$a_01_1 = {ff 15 6f 7f 1c 00 ff c0 48 98 48 8b d0 b9 40 00 00 00 ff 15 2d 7f 1c 00 48 89 45 28 48 8b 4d 28 ff 15 37 7f 1c 00 48 89 45 68 48 8b 55 48 48 8b 4d 68 ff 15 35 7f 1c 00 48 8b 4d 28 ff 15 13 7f 1c 00 33 c9 ff 15 3b 83 1c 00 ff 15 45 83 1c 00 48 8b 55 28 b9 01 00 00 00 ff 15 16 83 1c 00 ff 15 18 83 1c 00 } //00 00 
	condition:
		any of ($a_*)
 
}