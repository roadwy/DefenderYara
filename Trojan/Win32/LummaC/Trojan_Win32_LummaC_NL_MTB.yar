
rule Trojan_Win32_LummaC_NL_MTB{
	meta:
		description = "Trojan:Win32/LummaC.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 34 ca 34 19 35 46 35 4e 35 54 35 6a 35 75 35 7d 35 98 35 a3 35 db 35 e1 35 0d 36 28 36 62 36 6b 36 71 36 b0 36 b4 36 c4 36 c8 36 d8 36 dc 36 e0 36 e8 36 00 37 04 37 1c 37 2c 37 30 37 52 37 98 37 9e 37 d1 } //2
		$a_01_1 = {63 65 72 65 62 72 6f 74 6f 6e 69 61 2e 61 73 70 78 } //1 cerebrotonia.aspx
		$a_01_2 = {62 72 61 79 2e 78 6c 73 } //1 bray.xls
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}