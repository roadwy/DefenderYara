
rule Trojan_Win32_CryptBot_CD_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 45 08 0f af 45 0c 8b 0d 90 01 04 8d 14 81 89 55 fc b8 90 01 04 6b c8 90 01 01 ba 90 01 04 6b c2 90 01 01 8b 55 fc 8a 4c 0d 10 88 0c 02 ba 90 01 04 c1 e2 90 01 01 b8 90 01 04 c1 e0 90 01 01 8b 4d fc 8a 54 15 10 88 14 01 b8 90 01 04 6b c8 90 01 01 ba 90 01 04 6b c2 90 01 01 8b 55 fc 8a 4c 0d 10 88 0c 02 ba 90 01 04 d1 e2 b8 90 01 04 d1 e0 8b 4d fc 8a 54 15 10 88 14 01 90 00 } //03 00 
		$a_81_1 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //02 00 
		$a_81_2 = {47 65 74 54 68 72 65 61 64 54 69 6d 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}