
rule Trojan_Win64_ClipBanker_R_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 8d 15 d7 21 00 00 48 8d 8d 40 02 00 00 ff 15 90 01 02 00 00 48 8d 15 90 01 01 21 00 00 48 8b f8 48 8d 8d 40 03 00 00 ff 15 90 01 01 1f 00 00 8b 8d 34 01 00 00 48 8b f0 ff c1 48 63 c9 e8 90 01 01 01 00 00 4c 63 85 34 01 00 00 4d 8b ce ba 01 00 00 00 48 8b c8 48 8b d8 ff 15 90 01 01 1f 00 00 4c 63 85 34 01 00 00 4c 8b cf ba 01 00 00 00 48 8b cb ff 15 7d 1f 00 00 48 8b cf ff 15 90 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}