
rule Trojan_Win32_Fragtor_PGFG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.PGFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c3 0f b6 44 24 39 31 c9 3a 44 3e 01 0f 94 c1 e8 ?? ?? ?? ?? 88 c7 0f b6 44 24 3a 31 c9 20 df 3a 44 3e 02 0f 94 c1 e8 ?? ?? ?? ?? 88 44 24 0f 0f b6 44 24 3b 31 c9 3a 44 3e 03 0f 94 c1 e8 ?? ?? ?? ?? 88 c3 0f b6 44 24 3c 31 c9 22 5c 24 0f 20 fb 3a 44 3e 04 0f 94 c1 } //5
		$a_01_1 = {55 89 e5 83 ec 01 88 4d ff 0f b6 45 ff 83 c4 01 5d } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}