
rule Trojan_Win32_Convagent_NG_MTB{
	meta:
		description = "Trojan:Win32/Convagent.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 6b 73 65 73 20 49 6e 6a 65 63 74 } //2 Sukses Inject
		$a_01_1 = {6b 6f 61 6c 61 62 61 70 65 72 2e 63 6f 6d } //2 koalabaper.com
		$a_01_2 = {76 69 70 2d 66 6e 61 74 69 63 2e 63 6f 6d } //2 vip-fnatic.com
		$a_01_3 = {44 4c 4c 20 49 6e 6a 65 63 74 65 64 } //1 DLL Injected
		$a_01_4 = {48 61 72 61 70 20 42 75 6b 61 20 55 6c 61 6e 67 20 54 6f 6f 6c 73 20 49 6e 6a 65 63 74 69 6f 6e 20 41 74 61 75 20 48 75 62 75 6e 67 69 20 53 65 6c 6c 65 72 } //1 Harap Buka Ulang Tools Injection Atau Hubungi Seller
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}