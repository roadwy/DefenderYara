
rule Trojan_Win32_TrickBotCrypt_DQ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b da 03 1d 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 2b d9 03 1d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 2b da 8b 4d 90 01 01 8a 14 01 32 d3 8b 45 90 01 01 8b 08 8b 45 90 01 01 88 14 08 e9 90 00 } //1
		$a_81_1 = {36 4f 3f 6a 4d 32 4d 35 77 6b 57 69 4e 29 53 44 67 41 55 79 44 72 5e 2b 6d 26 21 5a 2a 58 74 74 43 5e 4d 66 29 75 34 28 24 77 36 6c 38 6e 37 42 48 77 3e 53 2b 67 3f 3e 6e 68 35 67 6a 49 43 6f 55 38 49 77 51 63 48 2b 35 41 6c 4a 6d 6f 55 21 6f 32 6e } //1 6O?jM2M5wkWiN)SDgAUyDr^+m&!Z*XttC^Mf)u4($w6l8n7BHw>S+g?>nh5gjICoU8IwQcH+5AlJmoU!o2n
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}