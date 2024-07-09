
rule Trojan_Win32_Emotet_DCC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 0f b6 0c 02 51 e8 ?? ?? ?? ?? 88 07 83 c4 10 (83 c7 01|47) 83 6c 24 ?? 01 75 } //5
		$a_81_1 = {53 45 52 54 49 46 49 43 41 54 } //2 SERTIFICAT
		$a_81_2 = {53 6c 6f 67 61 6e } //2 Slogan
		$a_81_3 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //1 CryptAcquireContextA
		$a_02_4 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 0f b6 0c 33 8a d9 f6 d3 0f b6 44 14 ?? 8a d0 f6 d2 0a d3 8b 9c 24 ?? ?? ?? ?? 0a c1 22 d0 85 f6 88 14 33 } //5
		$a_02_5 = {03 c2 99 f7 fb 0f b6 04 32 8b 54 24 ?? 0f be 14 0a 8a d8 f6 d2 f6 d3 0a da 8b 54 24 ?? 0f be 14 0a 0a c2 22 d8 8b 44 24 ?? 88 19 } //5
	condition:
		((#a_02_0  & 1)*5+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_02_4  & 1)*5+(#a_02_5  & 1)*5) >=5
 
}