
rule TrojanSpy_Win32_Bancos_XD{
	meta:
		description = "TrojanSpy:Win32/Bancos.XD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 73 6e 48 6f 74 74 00 } //1 獍䡮瑯t
		$a_00_1 = {70 00 70 00 73 00 65 00 63 00 75 00 72 00 65 00 2f 00 70 00 6f 00 73 00 74 00 2e 00 73 00 72 00 66 00 3f 00 77 00 61 00 3d 00 77 00 73 00 69 00 67 00 6e 00 69 00 6e 00 31 00 2e 00 30 00 26 00 72 00 70 00 73 00 6e 00 76 00 3d 00 } //1 ppsecure/post.srf?wa=wsignin1.0&rpsnv=
		$a_03_2 = {8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 90 01 01 83 ef 08 8b cf 8b 5d f0 d3 eb 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}