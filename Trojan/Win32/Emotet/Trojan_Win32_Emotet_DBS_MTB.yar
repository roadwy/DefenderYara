
rule Trojan_Win32_Emotet_DBS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 8c 8a 4c 15 ?? 30 08 40 83 bd ?? ?? ?? ?? 00 89 45 8c 0f 85 } //5
		$a_00_1 = {44 4f 4b 55 44 4f } //2 DOKUDO
		$a_81_2 = {65 72 7a 47 47 57 47 34 74 67 32 7a 79 7a 65 } //1 erzGGWG4tg2zyze
		$a_81_3 = {61 7a 67 61 34 61 67 33 67 33 71 67 } //1 azga4ag3g3qg
		$a_81_4 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //1 CryptAcquireContextA
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}