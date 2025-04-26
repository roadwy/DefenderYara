
rule Trojan_Win64_CobaltStrike_GD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe e8 15 04 00 eb 2d } //5
		$a_01_1 = {73 65 74 75 70 } //4 setup
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}
rule Trojan_Win64_CobaltStrike_GD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f0 } //1
		$a_01_1 = {45 8a 14 11 } //1
		$a_01_2 = {44 30 14 0f } //1 い༔
		$a_02_3 = {48 89 c8 48 81 f9 [0-04] 76 } //1
		$a_01_4 = {6f 6e 5f 61 76 61 73 74 5f 64 6c 6c 5f 75 6e 6c 6f 61 64 } //1 on_avast_dll_unload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}