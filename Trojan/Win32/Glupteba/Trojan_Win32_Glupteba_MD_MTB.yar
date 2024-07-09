
rule Trojan_Win32_Glupteba_MD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 f1 8b 4d f8 81 45 f8 ?? ?? ?? ?? 8b c7 c1 e8 05 03 45 e8 03 cf 33 f1 33 f0 2b de ff 4d f4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 fc 0f 85 ?? ?? ?? ?? 8b 45 08 89 78 04 5f 5e 89 18 5b c9 c2 } //3
		$a_00_1 = {63 00 69 00 72 00 61 00 62 00 6f 00 64 00 61 00 } //1 ciraboda
		$a_00_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 64 } //1 VirtualProtecd
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}