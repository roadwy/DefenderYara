
rule Trojan_Win32_Zonsterarch_V{
	meta:
		description = "Trojan:Win32/Zonsterarch.V,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 4d 5f 53 4d 53 05 50 4d 5f 57 4d 06 50 4d 5f 49 56 52 09 50 4d 5f 50 61 79 50 61 6c 09 50 4d 5f 43 72 65 64 69 74 05 50 4d 5f 56 4b } //2
		$a_01_1 = {2f 2f 63 6f 75 6e 74 72 79 5b 40 63 69 64 3d 22 25 73 22 5d 2f 62 61 73 65 5b 40 63 6f 73 74 3d 22 25 73 22 5d 2f 70 72 69 63 65 5b 40 73 75 62 3d } //2 //country[@cid="%s"]/base[@cost="%s"]/price[@sub=
		$a_11_2 = {00 61 00 79 00 6d 00 65 00 6e 00 74 00 5f 00 73 00 6d 00 73 00 5f 00 63 00 6f 00 73 00 74 00 3d 00 31 00 35 00 30 00 01 } //1
		$a_7a_3 = {70 63 6f 6e 6e 65 63 74 2e 69 6e 3c 2f 61 6c 74 5f } //8192 pconnect.in</alt_
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_11_2  & 1)*1+(#a_7a_3  & 1)*8192) >=4
 
}