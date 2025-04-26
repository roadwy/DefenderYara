
rule Trojan_Win32_Glupteba_GC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ff 69 04 00 00 75 ?? ?? ?? ?? ?? ?? ?? ff d5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 7c 8b 8d [0-20] 89 78 [0-20] 89 08 } //1
		$a_02_1 = {8b cf c1 e9 ?? 03 8d [0-20] 03 85 [0-20] 89 35 [0-20] 33 c1 8b 8d [0-20] 03 cf 33 c1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}