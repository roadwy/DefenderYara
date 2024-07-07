
rule Trojan_Win32_Plugx_V_dha{
	meta:
		description = "Trojan:Win32/Plugx.V!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 cd cc cc cc f7 e1 c1 ea 03 8d 14 92 03 d2 8b c1 2b c2 8a 90 20 9b 00 10 30 14 31 41 3b cf 7c df } //1
		$a_03_1 = {55 8b ec 81 ec 28 03 00 00 a3 90 01 04 89 0d 90 01 04 89 15 90 01 04 89 1d 90 01 04 89 35 90 01 04 89 3d 90 01 04 66 8c 15 90 01 04 66 8c 0d 90 01 04 66 8c 1d 90 01 04 66 8c 05 90 01 04 66 8c 25 90 01 04 66 8c 2d 90 01 04 9c 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Plugx_V_dha_2{
	meta:
		description = "Trojan:Win32/Plugx.V!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 85 f6 90 01 02 03 cb 8a 54 07 01 32 14 29 40 3b c6 88 11 90 01 02 8b 4c 24 90 01 01 8b 54 24 90 01 01 8d 42 90 01 01 3b d8 76 90 01 01 51 68 90 01 04 ff 15 90 01 04 8b 4c 90 01 02 8b 54 90 01 02 83 c4 90 01 01 43 3b da 72 90 00 } //1
		$a_03_1 = {8b 45 fc 33 c9 85 c0 90 01 02 8b 45 90 01 01 03 c6 03 d8 8a 54 0f 90 01 01 32 13 41 3b 4d 90 01 01 88 10 72 90 01 01 8b 5d 90 01 01 8b 45 90 01 01 83 c0 90 01 01 3b f0 90 01 02 ff 90 01 02 68 90 01 04 e8 90 01 04 59 59 46 3b 75 0c 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}