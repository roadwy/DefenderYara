
rule Trojan_Win32_Farfli_MA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 44 24 0c b9 fe 00 00 00 25 ff 00 00 00 56 99 f7 f9 8b 74 24 0c 80 c2 08 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //1
		$a_00_1 = {8a 50 01 40 80 fa 22 74 29 84 d2 74 25 0f b6 d2 f6 82 } //1
		$a_00_2 = {ff 01 85 f6 74 d5 8a 10 88 16 46 eb ce } //1
		$a_03_3 = {88 84 05 ec ?? ?? ?? 40 3b c6 72 f4 8a 45 ?? c6 85 ec ?? ?? ?? ?? 84 c0 74 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Farfli_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {f5 56 86 de fb 3e 34 3b d6 48 dc ea 07 cb 4c f0 50 c9 d0 89 f8 6a ca 1a 3d 7f e1 dd 2d 83 0b 9d } //5
		$a_01_1 = {4a 70 9f 20 59 4a dd 0d 38 76 8b ca be 19 64 de 7b ea 83 81 d9 d8 fd 9d d5 be 6a 93 cf 54 9c 22 } //5
		$a_01_2 = {38 77 56 57 eb c0 51 a3 df 56 5b 23 f5 02 c1 a3 3d cd b2 94 31 1e 95 15 4e 46 34 33 c6 04 61 28 } //5
		$a_01_3 = {49 6e 69 74 43 6f 6d 6d 6f 6e 43 6f 6e 74 72 6f 6c 73 } //1 InitCommonControls
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=16
 
}