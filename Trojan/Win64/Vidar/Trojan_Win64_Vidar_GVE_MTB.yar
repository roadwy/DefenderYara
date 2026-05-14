
rule Trojan_Win64_Vidar_GVE_MTB{
	meta:
		description = "Trojan:Win64/Vidar.GVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 3c 38 30 44 33 10 48 ff c3 48 81 fb 00 fc 06 00 72 a1 } //2
		$a_01_1 = {48 8b fb 83 e7 0f 75 42 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}