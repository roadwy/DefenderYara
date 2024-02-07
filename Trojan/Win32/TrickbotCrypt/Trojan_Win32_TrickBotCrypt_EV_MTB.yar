
rule Trojan_Win32_TrickBotCrypt_EV_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 bb 05 18 00 00 f7 f3 a1 90 01 04 03 55 e0 8d 14 42 03 55 dc 8b 45 f8 03 15 90 01 04 40 03 15 90 01 04 89 45 f8 8a 1c 0a 8b 55 fc 30 5c 02 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_EV_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 8b 45 f4 2b 05 90 01 04 2b 05 90 01 04 2b 05 90 01 04 8b 4d 0c 88 14 01 e9 90 00 } //01 00 
		$a_81_1 = {71 42 3c 53 4f 54 67 40 69 65 76 4e 5f 6a 4a 42 49 67 54 46 61 64 4f 65 35 62 78 41 2a 71 6b 5e 44 46 6e 47 26 45 47 31 23 6e 3e 54 73 30 61 28 67 34 2a 3c 4d 41 24 43 44 33 58 54 53 6e 35 39 5f 6f 66 75 43 31 78 75 78 3e 2b 25 53 48 46 74 3c 4a 42 66 58 6f 33 38 53 48 4e 36 4b 35 72 41 56 29 59 6d 44 52 2a 34 76 63 62 36 5e 73 43 52 38 4f 4f } //00 00  qB<SOTg@ievN_jJBIgTFadOe5bxA*qk^DFnG&EG1#n>Ts0a(g4*<MA$CD3XTSn59_ofuC1xux>+%SHFt<JBfXo38SHN6K5rAV)YmDR*4vcb6^sCR8OO
	condition:
		any of ($a_*)
 
}