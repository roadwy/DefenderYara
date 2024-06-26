
rule Trojan_Win32_Emotet_DCC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 05 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 90 01 04 f7 f9 8b 44 24 90 01 01 0f b6 0c 02 51 e8 90 01 04 88 07 83 c4 10 90 03 03 01 83 c7 01 47 83 6c 24 90 01 01 01 75 90 00 } //02 00 
		$a_81_1 = {53 45 52 54 49 46 49 43 41 54 } //02 00  SERTIFICAT
		$a_81_2 = {53 6c 6f 67 61 6e } //01 00  Slogan
		$a_81_3 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //05 00  CryptAcquireContextA
		$a_02_4 = {03 c1 99 b9 90 01 04 f7 f9 0f b6 0c 33 8a d9 f6 d3 0f b6 44 14 90 01 01 8a d0 f6 d2 0a d3 8b 9c 24 90 01 04 0a c1 22 d0 85 f6 88 14 33 90 00 } //05 00 
		$a_02_5 = {03 c2 99 f7 fb 0f b6 04 32 8b 54 24 90 01 01 0f be 14 0a 8a d8 f6 d2 f6 d3 0a da 8b 54 24 90 01 01 0f be 14 0a 0a c2 22 d8 8b 44 24 90 01 01 88 19 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}