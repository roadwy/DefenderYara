
rule Trojan_Win32_MatanbuchusLoader_DG_MTB{
	meta:
		description = "Trojan:Win32/MatanbuchusLoader.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {45 42 6f 65 51 52 49 77 2e 64 6c 6c } //2 EBoeQRIw.dll
		$a_01_1 = {44 76 4d 4f 49 57 68 39 4c 4f } //1 DvMOIWh9LO
		$a_01_2 = {45 68 67 59 4c 34 44 } //1 EhgYL4D
		$a_01_3 = {46 6f 56 6b 58 38 47 6e 34 } //1 FoVkX8Gn4
		$a_01_4 = {4d 5a 34 48 6b 52 48 70 4a } //1 MZ4HkRHpJ
		$a_01_5 = {59 62 74 41 57 4d 54 63 48 59 } //1 YbtAWMTcHY
		$a_01_6 = {66 44 4e 41 61 50 64 31 72 79 72 } //1 fDNAaPd1ryr
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}