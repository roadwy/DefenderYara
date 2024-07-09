
rule Trojan_Win32_Emotet_DCA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 07 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 83 c0 01 83 c4 0c 89 44 24 ?? 8a 54 14 ?? 30 50 ff 83 bc 24 ?? ?? ?? ?? 00 0f 85 } //50
		$a_02_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 18 8a 54 14 ?? 32 da 88 18 } //50
		$a_02_2 = {03 c2 83 c4 0c 99 f7 f9 8b 44 24 ?? 8a 08 8a 54 14 ?? 32 ca 88 08 } //50
		$a_81_3 = {47 46 44 53 67 66 73 64 64 73 64 53 41 44 53 64 } //20 GFDSgfsddsdSADSd
		$a_81_4 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //5 CryptAcquireContextA
		$a_81_5 = {47 46 44 53 47 48 44 46 48 44 47 44 46 44 72 64 66 64 66 } //20 GFDSGHDFHDGDFDrdfdf
		$a_81_6 = {4d 41 4c 54 41 } //5 MALTA
	condition:
		((#a_02_0  & 1)*50+(#a_02_1  & 1)*50+(#a_02_2  & 1)*50+(#a_81_3  & 1)*20+(#a_81_4  & 1)*5+(#a_81_5  & 1)*20+(#a_81_6  & 1)*5) >=50
 
}