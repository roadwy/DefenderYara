
rule Trojan_Win32_DanaBot_GL_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 57 c0 33 c8 66 0f 13 05 90 02 30 81 3d 90 02 35 89 4c 24 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_DanaBot_GL_MTB_2{
	meta:
		description = "Trojan:Win32/DanaBot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 d6 33 ca 81 3d 90 02 15 c7 05 90 02 15 89 1d 90 02 15 89 8d 90 00 } //1
		$a_00_1 = {8b 85 d8 f7 ff ff 8b 4d fc 89 78 04 5f 89 30 5e 33 cd 5b e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}