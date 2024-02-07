
rule Trojan_Win32_Qakbot_DP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 9c 8b 55 d8 01 02 8b 45 b4 83 e8 2c 03 45 9c 89 45 b0 8b 45 cc 03 45 b0 8b 55 d8 31 02 83 45 9c 04 8b 45 d8 83 c0 04 89 45 d8 8b 45 9c 99 52 50 8b 45 d4 33 d2 3b 54 24 04 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_DP_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 5a 31 33 6c 69 73 74 54 6f 56 61 72 69 61 6e 74 49 31 32 4b 41 62 6f 75 74 50 65 72 73 6f 6e 45 35 51 4c 69 73 74 49 38 51 56 61 72 69 61 6e 74 45 52 4b 53 31 5f 49 54 5f 45 } //02 00  RZ13listToVariantI12KAboutPersonE5QListI8QVariantERKS1_IT_E
		$a_01_1 = {52 5a 31 39 73 74 61 6c 65 4d 61 74 63 68 65 73 4d 61 6e 61 67 65 64 52 4b 37 51 53 74 72 69 6e 67 52 4b 34 51 55 72 6c } //02 00  RZ19staleMatchesManagedRK7QStringRK4QUrl
		$a_01_2 = {52 5a 35 71 48 61 73 68 52 4b 37 4b 55 73 65 72 49 64 6a } //02 00  RZ5qHashRK7KUserIdj
		$a_01_3 = {52 5a 4e 31 30 4b 41 62 6f 75 74 44 61 74 61 31 38 66 72 6f 6d 50 6c 75 67 69 6e 4d 65 74 61 44 61 74 61 45 52 4b 31 35 4b 50 6c 75 67 69 6e 4d 65 74 61 44 61 74 61 } //02 00  RZN10KAboutData18fromPluginMetaDataERK15KPluginMetaData
		$a_01_4 = {52 5a 4e 31 30 4b 55 73 65 72 47 72 6f 75 70 43 31 45 4e 35 4b 55 73 65 72 37 55 49 44 4d 6f 64 65 45 } //00 00  RZN10KUserGroupC1EN5KUser7UIDModeE
	condition:
		any of ($a_*)
 
}