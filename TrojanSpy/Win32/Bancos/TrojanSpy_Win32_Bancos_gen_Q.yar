
rule TrojanSpy_Win32_Bancos_gen_Q{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 45 ec 8b 45 ec 0f b6 00 8b 95 d4 fe ff ff 30 84 15 d8 fe ff ff ff 85 d4 fe ff ff 81 bd d4 fe ff ff 00 01 00 00 75 90 01 01 33 d2 89 95 d4 fe ff ff 8b 55 d8 30 44 15 dc ff 45 d8 83 7d d8 08 75 90 00 } //1
		$a_01_1 = {03 d0 03 c2 8b fa c1 ef 07 33 d7 03 ca 03 d1 8b f9 c1 e7 0d 33 cf 03 d9 03 cb 8b fb c1 ef 11 33 df 03 c3 03 d8 8b f8 c1 e7 09 33 c7 03 d0 03 c2 8b fa c1 ef 03 33 d7 03 ca 03 d1 8b f9 c1 e7 07 33 cf 03 d9 03 cb 8b f8 c1 ef 0f 33 df 03 c3 03 d8 8b f8 c1 e7 0b 33 c7 4e } //1
		$a_01_2 = {43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 43 70 6c 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 } //1
		$a_03_3 = {8b 08 ff 51 1c 8b 85 90 01 01 fa ff ff 8d 95 90 01 01 fa ff ff e8 90 01 04 ff b5 90 01 01 fa ff ff 8d 85 90 01 01 fa ff ff ba 06 90 00 } //5
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*5) >=7
 
}