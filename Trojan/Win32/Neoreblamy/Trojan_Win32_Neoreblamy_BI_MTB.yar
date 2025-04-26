
rule Trojan_Win32_Neoreblamy_BI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {2b c8 0f b6 45 ?? 0f af 45 ?? 03 c8 89 4d } //3
		$a_03_1 = {2b c8 0f af 4d ?? 03 d1 0f b6 4d } //2
		$a_01_2 = {48 69 61 74 44 4e 66 56 46 51 4e 72 55 4c 68 4a 6e 45 6c 77 67 70 77 6c 64 56 66 } //2 HiatDNfVFQNrULhJnElwgpwldVf
		$a_01_3 = {49 62 59 61 73 53 46 55 72 58 55 55 64 71 43 73 64 66 70 66 41 41 66 6f 63 42 42 57 66 78 4b 51 55 } //1 IbYasSFUrXUUdqCsdfpfAAfocBBWfxKQU
		$a_01_4 = {6c 74 62 4e 4e 58 62 6d 50 4b 74 71 47 69 65 55 45 4a 71 4b 68 6f 55 6f 52 4f 58 47 7a 74 68 49 74 44 } //1 ltbNNXbmPKtqGieUEJqKhoUoROXGzthItD
		$a_01_5 = {7a 79 6f 56 4c 55 41 75 6e 79 44 46 41 55 54 56 77 61 64 4b 41 79 6c 49 41 76 75 67 43 } //1 zyoVLUAunyDFAUTVwadKAylIAvugC
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}