
rule Trojan_Win32_Dridex_AMH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {c4 fd 14 e0 64 da 32 01 f9 51 16 72 d6 8d f9 aa 29 23 9f cd e8 64 36 8e 19 f6 6f fb bd 5a 62 0b } //10
		$a_80_1 = {55 72 6c 55 6e 65 73 63 61 70 65 57 } //UrlUnescapeW  3
		$a_80_2 = {4d 70 72 41 64 6d 69 6e 49 6e 74 65 72 66 61 63 65 54 72 61 6e 73 70 6f 72 74 41 64 64 } //MprAdminInterfaceTransportAdd  3
		$a_80_3 = {47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 57 } //GetUrlCacheEntryInfoW  3
		$a_80_4 = {43 72 79 70 74 43 41 54 50 75 74 41 74 74 72 49 6e 66 6f } //CryptCATPutAttrInfo  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}