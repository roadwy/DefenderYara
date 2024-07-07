
rule Trojan_Win32_Dofoil_DSK_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {88 45 fc 8a 06 0c 01 0f b6 f8 89 d8 99 f7 ff 0f b6 3e 01 f8 88 01 8a 45 fc } //2
		$a_02_1 = {88 3e d2 e0 88 07 eb 90 01 01 89 d7 8a 00 0c 01 0f b6 c8 89 d8 99 f7 f9 0f b6 0e 01 c8 8a 0f 88 dc 88 cf d2 e4 00 e7 88 d9 eb d7 90 00 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}