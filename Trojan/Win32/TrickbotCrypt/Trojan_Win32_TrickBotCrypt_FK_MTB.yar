
rule Trojan_Win32_TrickBotCrypt_FK_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 03 c8 2b 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 03 ca 2b 0d 90 01 04 2b 0d 90 01 04 a1 90 01 04 0f af 05 90 01 04 2b c8 2b 0d 90 01 04 8b 55 f8 2b 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 2b d0 2b 15 90 01 04 2b 15 90 01 04 03 15 90 01 04 03 15 90 01 04 8b 45 0c 8b 75 08 8a 0c 08 32 0c 16 90 00 } //1
		$a_81_1 = {7a 37 75 5e 59 46 3e 3f 44 7a 77 5a 66 55 3e 42 2b 74 6f 21 32 43 69 79 48 79 52 78 53 63 55 73 63 41 74 6b 4d 47 55 3e 52 65 46 50 63 65 45 4b 23 72 67 5f 71 4e 42 47 3c 74 4d 21 34 5f 72 63 4e 5a 31 41 4d 54 4e 6e 31 35 32 3f 55 59 55 4f 4c 78 53 6c 63 2a 59 4e 56 61 6e 35 77 26 } //1 z7u^YF>?DzwZfU>B+to!2CiyHyRxScUscAtkMGU>ReFPceEK#rg_qNBG<tM!4_rcNZ1AMTNn152?UYUOLxSlc*YNVan5w&
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}