
rule Trojan_BAT_Bladabindi_NV_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c } //5
		$a_01_1 = {08 84 95 d7 6e 20 ff 00 00 00 6a 5f b8 0d 1b } //3
		$a_01_2 = {08 6e 17 6a d6 20 ff 00 00 00 6a 5f b8 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}
rule Trojan_BAT_Bladabindi_NV_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {26 07 16 28 ?? ?? ?? 0a 0c 06 16 73 ?? ?? ?? 0a 0d 08 8d ?? ?? ?? 01 13 04 } //1
		$a_01_1 = {57 b5 a2 3d 09 07 00 00 00 00 00 00 00 00 00 00 02 00 00 00 67 00 00 00 18 00 00 00 26 00 00 00 8b 00 00 00 26 00 00 00 71 00 00 00 24 00 00 00 05 } //1
		$a_01_2 = {33 33 32 62 65 34 64 38 39 36 35 30 } //1 332be4d89650
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}