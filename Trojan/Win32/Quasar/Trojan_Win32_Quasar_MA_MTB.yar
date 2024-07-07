
rule Trojan_Win32_Quasar_MA_MTB{
	meta:
		description = "Trojan:Win32/Quasar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {cd 0a 0e 97 1f 9a 76 af f4 f0 4d eb 25 c4 1e a5 3d 9c cc 56 0c 46 e5 90 d6 7b 0f 6e 50 30 75 da } //5
		$a_01_1 = {f9 b8 d0 90 b5 5d 90 a5 32 b2 c5 b7 76 10 67 0f 30 10 b1 af 9b 0f ea cb 4f 08 6a 4f b4 f4 51 f2 } //5
		$a_01_2 = {03 fd b6 90 9e 11 b7 01 6f 1e dd b6 40 08 4a 36 b4 76 a6 e6 4a fb f7 e5 97 9f f2 5f 05 2e 96 72 } //5
		$a_01_3 = {49 6e 69 74 43 6f 6d 6d 6f 6e 43 6f 6e 74 72 6f 6c 73 } //1 InitCommonControls
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=16
 
}