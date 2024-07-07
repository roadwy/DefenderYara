
rule Trojan_Win32_Ursnif_MFP_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_00_0 = {bb b2 72 35 fc ba bf 3a 15 4b 0f 45 d3 85 f9 89 44 24 50 0f 94 44 24 2c 0f 45 da 83 fe 0a 0f 9c 44 24 38 0f 4d da 41 b8 bf 3a 15 4b b9 66 66 41 c9 be 4b c4 69 10 31 ff 81 f9 4a c4 69 10 } //5
		$a_02_1 = {0f af f0 89 f0 83 f0 90 01 01 85 f0 40 0f 94 c5 83 fa 0a 0f 9c c3 40 30 eb bb 6c 95 b0 0f bf b2 df 8f 21 0f 45 df 85 f0 89 dd 0f 44 ef 83 fa 0a 4c 89 4c 24 08 0f 4d eb 90 00 } //5
		$a_02_2 = {0f af d0 89 d0 83 f0 90 01 01 85 d0 41 0f 94 c0 83 f9 0a 0f 9c c3 44 30 c3 bb 61 20 ca 7d be a9 33 3d 09 0f 45 de 85 d0 89 d8 0f 44 c6 83 f9 0a 8b 4c 24 5c 0f 4d c3 3b 0d 96 6f 02 90 00 } //5
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5) >=10
 
}