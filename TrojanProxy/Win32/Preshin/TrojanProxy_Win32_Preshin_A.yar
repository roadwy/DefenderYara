
rule TrojanProxy_Win32_Preshin_A{
	meta:
		description = "TrojanProxy:Win32/Preshin.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 4e 53 54 52 00 } //1 乂呓R
		$a_01_1 = {44 65 6c 65 74 65 64 20 4f 45 20 41 63 63 6f 75 6e 74 00 } //1
		$a_01_2 = {41 6e 6f 6e 79 20 50 72 6f 78 79 20 52 65 63 76 } //1 Anony Proxy Recv
		$a_01_3 = {25 73 67 73 74 2e 70 61 63 } //1 %sgst.pac
		$a_01_4 = {54 72 75 65 20 50 72 6f 78 79 20 69 73 20 6e 6f 74 20 61 76 61 69 6c 61 62 65 6c 21 } //1 True Proxy is not availabel!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}