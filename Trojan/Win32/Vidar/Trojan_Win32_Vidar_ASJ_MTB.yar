
rule Trojan_Win32_Vidar_ASJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c6 59 8b 4c 24 24 0f b6 c0 8a 44 04 30 30 04 0a 41 89 4c 24 24 3b 0f 7c } //4
		$a_01_1 = {23 c9 66 f7 e2 33 f2 46 42 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}