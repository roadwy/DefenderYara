
rule Trojan_Win32_Emotet_SK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {4f 23 77 77 23 50 23 23 23 23 23 23 23 77 4f } //01 00  O#ww#P#######wO
		$a_81_1 = {59 55 51 39 46 2a 6d 69 4f 71 } //01 00  YUQ9F*miOq
		$a_81_2 = {36 21 68 40 4a 30 56 69 23 4f } //01 00  6!h@J0Vi#O
		$a_81_3 = {6e 69 37 3d 38 68 4c 4f 36 6f } //00 00  ni7=8hLO6o
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_SK_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {eb 00 8b 55 90 01 01 3b 15 90 01 04 72 02 eb 42 8b 45 90 01 01 89 45 90 01 01 c7 45 90 01 05 8b 4d 90 01 01 03 4d 90 01 01 c6 01 00 c7 45 90 01 01 00 00 00 00 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 8a 08 88 0a c7 45 90 01 05 8b 55 90 01 01 83 c2 01 89 55 90 01 01 e9 90 01 01 ff ff ff 8b e5 5d c3 90 00 } //02 00 
		$a_02_1 = {55 8b ec 81 ec b0 00 00 00 c7 45 90 01 01 40 00 00 00 c7 45 90 01 01 00 00 00 00 a1 90 01 04 89 45 90 01 01 c7 45 90 01 01 ff ff ff ff c6 45 90 01 01 0d 8b 0d 90 01 04 89 0d 90 01 04 ff 75 90 01 01 68 00 30 00 00 8b 45 90 01 01 50 ff 75 90 01 01 ff 35 90 01 04 59 a1 90 01 04 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}