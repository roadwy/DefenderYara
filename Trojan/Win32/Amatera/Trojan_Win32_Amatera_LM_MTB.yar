
rule Trojan_Win32_Amatera_LM_MTB{
	meta:
		description = "Trojan:Win32/Amatera.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 b4 18 00 00 00 c7 45 b8 00 00 00 00 8d 55 cc 89 55 bc c7 45 c0 40 00 00 00 c7 45 e4 00 00 00 00 c6 45 f8 4e c6 45 f9 74 c6 45 fa 00 c6 45 d4 4f c6 45 d5 70 c6 45 d6 65 c6 45 d7 6e c6 45 d8 00 c6 45 f4 4b c6 45 f5 65 c6 45 f6 79 c6 45 f7 00 8d 45 d4 } //20
		$a_01_1 = {83 c4 0c c6 45 fc 4e c6 45 fd 74 c6 45 fe 00 c6 45 d0 44 c6 45 d1 65 c6 45 d2 76 c6 45 d3 69 c6 45 d4 63 c6 45 d5 65 c6 45 d6 00 c6 45 f8 49 c6 45 f9 6f c6 45 fa 00 c6 45 c8 43 c6 45 c9 6f c6 45 ca 6e c6 45 cb 74 c6 45 cc 72 c6 45 cd 6f c6 45 ce 6c c6 45 cf 00 c6 45 d8 46 c6 45 d9 69 c6 45 da 6c c6 45 db 65 c6 45 dc 00 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}