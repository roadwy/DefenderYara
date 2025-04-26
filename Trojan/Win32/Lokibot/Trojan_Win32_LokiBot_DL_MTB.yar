
rule Trojan_Win32_LokiBot_DL_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 0f be 80 ?? ?? ?? ?? 83 f0 ?? 8b 8d 5c ff ff ff 03 4d f0 88 01 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 7f 07 c6 05 f5 45 00 10 ?? 0f bf 05 ?? ?? ?? ?? 85 c0 74 12 0f bf 05 ?? ?? ?? ?? 85 c0 74 07 c6 05 ?? ?? ?? ?? ?? 8b 45 f0 40 89 45 f0 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LokiBot_DL_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c2 03 c3 90 05 05 01 90 c6 [0-04] 90 05 05 01 90 43 81 fb [0-04] 75 ec } //1
		$a_02_1 = {33 c0 89 45 [0-04] 33 c9 90 05 05 01 90 8b c1 90 05 10 01 90 8a 90 90 [0-04] 90 05 10 01 90 80 f2 e3 90 05 10 01 90 8b c6 03 c1 90 05 10 01 90 89 45 fc 90 05 10 01 90 88 55 fb 90 05 10 01 90 8b 55 fc 90 05 10 01 90 8a 45 fb 90 05 10 01 90 88 02 90 05 05 01 90 41 81 f9 ?? ?? ?? ?? 75 bf } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}