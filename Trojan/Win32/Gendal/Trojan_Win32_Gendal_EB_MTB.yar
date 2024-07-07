
rule Trojan_Win32_Gendal_EB_MTB{
	meta:
		description = "Trojan:Win32/Gendal.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 72 61 6e 6b 5c 44 65 73 6b 74 6f 70 5c 4c 4d 71 42 48 46 51 6c 2e 65 78 65 } //1 Frank\Desktop\LMqBHFQl.exe
		$a_01_1 = {43 72 65 61 74 65 53 74 72 65 61 6d 4f 6e 48 47 6c 6f 62 61 6c } //1 CreateStreamOnHGlobal
		$a_01_2 = {50 72 65 76 69 6f 75 73 20 50 69 63 74 75 72 65 } //1 Previous Picture
		$a_01_3 = {4b 6f 64 61 6b 20 56 69 65 77 65 72 20 45 78 70 72 65 73 73 } //1 Kodak Viewer Express
		$a_01_4 = {58 58 58 58 52 4c 4c 4c 4c 4c 4c 4c 52 58 58 58 58 4c 4c 4c 4c 4c 4c 4c 4c 52 58 58 58 58 } //1 XXXXRLLLLLLLRXXXXLLLLLLLLRXXXX
		$a_01_5 = {58 58 58 58 4c 46 46 46 46 46 46 4c 52 58 58 52 4c 46 46 46 46 46 46 46 46 4c 58 58 58 58 } //1 XXXXLFFFFFFLRXXRLFFFFFFFFLXXXX
		$a_01_6 = {58 58 58 58 4c 46 4c 52 46 46 52 52 52 52 4c 52 52 4c 52 52 52 52 52 52 46 4c 58 58 58 58 } //1 XXXXLFLRFFRRRRLRRLRRRRRRFLXXXX
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}