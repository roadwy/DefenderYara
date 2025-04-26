
rule Trojan_Win32_InjectPyinc_SA{
	meta:
		description = "Trojan:Win32/InjectPyinc.SA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 70 79 69 62 6f 6f 74 30 31 5f 62 6f 6f 74 73 74 72 61 70 } //1 spyiboot01_bootstrap
		$a_01_1 = {62 43 72 79 70 74 6f 2e 43 69 70 68 65 72 2e 5f 41 45 53 2e 70 79 64 } //1 bCrypto.Cipher._AES.pyd
		$a_01_2 = {62 69 69 2e 65 78 65 2e 6d 61 6e 69 66 65 73 74 } //1 bii.exe.manifest
		$a_01_3 = {5c 5f 4d 45 49 33 38 30 34 32 5c } //1 \_MEI38042\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}