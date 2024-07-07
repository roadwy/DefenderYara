
rule Trojan_Win32_UrlRepE2ETest_A{
	meta:
		description = "Trojan:Win32/UrlRepE2ETest.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 64 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 } //10 certutil
		$a_00_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 74 00 68 00 69 00 73 00 63 00 61 00 6e 00 6e 00 6f 00 74 00 70 00 6f 00 73 00 73 00 69 00 62 00 6c 00 79 00 77 00 6f 00 72 00 6b 00 2e 00 6c 00 6f 00 63 00 61 00 6c 00 2f 00 } //90 https://thiscannotpossiblywork.local/
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*90) >=100
 
}