
rule Trojan_Win32_Emotet_DCA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 07 00 00 32 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 90 01 04 f7 f9 8b 44 24 90 01 01 83 c0 01 83 c4 0c 89 44 24 90 01 01 8a 54 14 90 01 01 30 50 ff 83 bc 24 90 01 04 00 0f 85 90 00 } //32 00 
		$a_02_1 = {03 c1 99 b9 90 01 04 f7 f9 8b 44 24 90 01 01 8a 18 8a 54 14 90 01 01 32 da 88 18 90 00 } //32 00 
		$a_02_2 = {03 c2 83 c4 0c 99 f7 f9 8b 44 24 90 01 01 8a 08 8a 54 14 90 01 01 32 ca 88 08 90 00 } //14 00 
		$a_81_3 = {47 46 44 53 67 66 73 64 64 73 64 53 41 44 53 64 } //05 00  GFDSgfsddsdSADSd
		$a_81_4 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //14 00  CryptAcquireContextA
		$a_81_5 = {47 46 44 53 47 48 44 46 48 44 47 44 46 44 72 64 66 64 66 } //05 00  GFDSGHDFHDGDFDrdfdf
		$a_81_6 = {4d 41 4c 54 41 } //00 00  MALTA
	condition:
		any of ($a_*)
 
}