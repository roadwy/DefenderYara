
rule Trojan_Win32_Emotet_PBM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 01 0f b6 ca 03 c1 25 ?? ?? ?? ?? 79 ?? 48 0d 00 ff ff ff 40 8a 84 05 ?? ?? ?? ?? 32 04 37 88 06 } //1
		$a_02_1 = {8a 04 0a 8b 4d ?? 8b 11 8b 4d ?? 33 db 8a 1c 11 33 c3 8b 15 ?? ?? ?? ?? 8b 0a 8b 55 ?? 88 04 0a } //1
		$a_81_2 = {62 4d 67 42 6f 32 53 31 2a 4b 69 7d 56 7e 35 6e 32 38 53 69 23 32 30 66 7e 7d 4d 34 4b 5a 3f 64 79 25 40 6e 43 4d 6e 54 51 4a 4c 63 2a 45 34 62 4a 7c 24 41 38 44 53 5a 6e 65 34 70 54 58 45 4a 25 40 50 66 58 33 6d 4b 42 67 76 58 61 } //1 bMgBo2S1*Ki}V~5n28Si#20f~}M4KZ?dy%@nCMnTQJLc*E4bJ|$A8DSZne4pTXEJ%@PfX3mKBgvXa
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}