
rule Trojan_Win32_TrickBotCrypt_FA_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 08 0f b6 95 90 01 04 33 ca 8b 85 90 01 04 2b 85 90 01 04 0f b6 d0 81 e2 ff 90 01 03 33 ca 8b 85 90 01 04 88 08 90 00 } //01 00 
		$a_81_1 = {43 68 65 63 6b 69 6e 67 20 70 72 6f 63 65 73 73 20 6f 66 20 6d 61 6c 77 61 72 65 20 61 6e 61 6c 79 73 69 73 20 74 6f 6f 6c 3a 20 25 73 } //01 00 
		$a_81_2 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //01 00 
		$a_81_3 = {6a 6f 65 62 6f 78 73 65 72 76 65 72 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}