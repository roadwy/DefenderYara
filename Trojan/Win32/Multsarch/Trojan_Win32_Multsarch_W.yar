
rule Trojan_Win32_Multsarch_W{
	meta:
		description = "Trojan:Win32/Multsarch.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_11_0 = {4d 5a 50 00 02 00 00 00 04 00 0f 00 ff ff 00 00 b8 00 a0 00 07 40 00 1a 00 00 00 fb 10 6a 72 01 } //1
		$a_83_1 = {20 0f b7 c0 83 c6 02 66 3b c2 75 90 14 0f b7 46 fe 8d 50 } //13824
	condition:
		((#a_11_0  & 1)*1+(#a_83_1  & 1)*13824) >=2
 
}