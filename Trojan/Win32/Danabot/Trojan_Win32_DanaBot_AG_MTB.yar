
rule Trojan_Win32_DanaBot_AG_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 d3 33 ca 81 3d [0-25] c7 05 [0-25] 89 2d [0-25] 89 2d [0-25] 89 4c 24 } //1
		$a_02_1 = {8b 44 24 38 89 78 04 [0-10] 89 18 5b 83 c4 2c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}