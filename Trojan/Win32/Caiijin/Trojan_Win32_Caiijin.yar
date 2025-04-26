
rule Trojan_Win32_Caiijin{
	meta:
		description = "Trojan:Win32/Caiijin,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6a 69 6e 67 63 61 69 2e 63 6f 6d 2f } //1 ijingcai.com/
		$a_01_1 = {5c 64 72 69 76 65 72 73 5c 6d 73 72 78 6d 63 62 2e 73 79 73 } //1 \drivers\msrxmcb.sys
		$a_01_2 = {5c 64 72 69 76 65 72 73 5c 74 64 61 63 2e 73 79 73 } //1 \drivers\tdac.sys
		$a_01_3 = {62 68 6f 62 68 6f 62 62 62 61 64 } //1 bhobhobbbad
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Caiijin_2{
	meta:
		description = "Trojan:Win32/Caiijin,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6a 69 6e 67 63 61 69 2e 63 6f 6d 2f 6b 65 79 77 6f 72 64 } //1 ijingcai.com/keyword
		$a_01_1 = {26 61 64 72 69 67 68 74 3d 25 73 } //1 &adright=%s
		$a_01_2 = {39 36 36 33 33 31 32 32 2d 30 31 30 33 2d 39 36 33 38 2d 32 39 36 34 2d 61 38 37 34 32 33 36 34 38 39 32 31 } //1 96633122-0103-9638-2964-a87423648921
		$a_01_3 = {31 32 33 36 35 34 38 34 2d 39 36 61 31 2d 36 39 37 34 2d 33 32 36 39 2d 31 32 33 35 35 35 31 32 34 36 35 35 } //1 12365484-96a1-6974-3269-123555124655
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}