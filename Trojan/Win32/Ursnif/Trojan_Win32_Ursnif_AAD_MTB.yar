
rule Trojan_Win32_Ursnif_AAD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 18 8b 54 24 14 81 c2 b8 ec 5a 01 89 54 24 14 89 17 0f b7 f9 89 15 90 01 04 8d 57 0d 89 54 24 2c 66 39 5c 24 0e 72 90 00 } //1
		$a_02_1 = {0f b6 44 24 0d 83 44 24 18 90 01 01 2b f8 83 c7 2f 03 fa ff 4c 24 24 74 90 01 01 8b 1d 90 01 04 8b 54 24 28 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}