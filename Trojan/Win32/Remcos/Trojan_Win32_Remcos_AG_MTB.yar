
rule Trojan_Win32_Remcos_AG_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 19 46 33 de 3b df 75 90 01 01 89 b4 95 90 01 04 42 41 81 fa ff 01 00 00 72 90 00 } //1
		$a_03_1 = {30 14 08 05 ff 01 00 00 3b c6 7c 90 01 01 47 81 ff ff 01 00 00 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}