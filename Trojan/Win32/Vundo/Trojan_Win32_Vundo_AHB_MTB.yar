
rule Trojan_Win32_Vundo_AHB_MTB{
	meta:
		description = "Trojan:Win32/Vundo.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e1 08 0f b6 d4 0f b6 85 32 fb ff ff 03 ca 0f b6 95 33 fb ff ff c1 e1 08 03 c8 c1 e1 08 03 ca 89 4e fe 83 c4 0c 83 c6 08 83 ef 01 0f 85 } //10
		$a_01_1 = {03 d3 c1 fa 03 8b c2 c1 e8 1f 03 c2 8b c8 c1 e1 04 2b c8 8b d3 2b d1 0f be 8c 15 34 ff ff ff 8d b4 15 34 ff ff ff b8 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}