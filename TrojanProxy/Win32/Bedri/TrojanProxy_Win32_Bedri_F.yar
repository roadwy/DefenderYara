
rule TrojanProxy_Win32_Bedri_F{
	meta:
		description = "TrojanProxy:Win32/Bedri.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 "
		
	strings :
		$a_01_0 = {c6 85 dc fd ff ff 25 c6 85 dd fd ff ff 73 c6 85 de fd ff ff 5c c6 85 df fd ff ff 73 c6 85 e0 fd ff ff 68 c6 85 e1 fd ff ff 65 c6 85 e2 fd ff ff 6c c6 85 e3 fd ff ff 6c c6 85 e4 fd ff ff 5c c6 85 e5 fd ff ff 6f c6 85 e6 fd ff ff 70 } //1
		$a_01_1 = {c6 85 78 fd ff ff 43 c6 85 79 fd ff ff 3a c6 85 7a fd ff ff 5c c6 85 7b fd ff ff 4d c6 85 7c fd ff ff 69 c6 85 7d fd ff ff 63 c6 85 7e fd ff ff 72 c6 85 7f fd ff ff 6f c6 85 80 fd ff ff 73 c6 85 81 fd ff ff 6f c6 85 82 fd ff ff 66 c6 85 83 fd ff ff 74 } //1
		$a_01_2 = {c6 45 cc 43 c6 45 cd 3a c6 45 ce 5c c6 45 cf 4d c6 45 d0 69 c6 45 d1 63 c6 45 d2 72 c6 45 d3 6f c6 45 d4 73 c6 45 d5 6f c6 45 d6 66 c6 45 d7 74 } //1
		$a_01_3 = {63 6c 61 72 6b 20 25 64 00 } //1
		$a_01_4 = {00 6f 73 74 00 48 00 } //1
		$a_03_5 = {ff ff 5c c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 63 c6 85 ?? ?? ff ff 5c } //1
		$a_01_6 = {c6 45 dc 5c c6 45 dd 69 c6 45 de 6e c6 45 df 63 c6 45 e0 5c } //1
		$a_01_7 = {4e 76 64 69 61 00 } //1 癎楤a
		$a_01_8 = {c6 45 d4 5c c6 45 d5 69 c6 45 d6 6e c6 45 d7 63 c6 45 d8 6c c6 45 d9 75 c6 45 da 64 c6 45 db 65 c6 45 dc 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=3
 
}