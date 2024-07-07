
rule Trojan_Win32_CryptInject_AX_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 73 76 68 6f 73 74 2e 65 78 65 } //1 \Downloads\svhost.exe
		$a_00_1 = {66 90 80 34 38 46 40 3b c6 7c f7 } //1
		$a_02_2 = {8b c1 83 e0 01 8a 84 05 90 01 02 ff ff 30 04 39 41 3b ce 7c ec 90 00 } //1
		$a_00_3 = {5c 73 75 70 70 6f 72 74 5f 63 72 69 70 74 5c } //1 \support_cript\
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}