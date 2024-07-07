
rule Trojan_Win32_Silbul_A{
	meta:
		description = "Trojan:Win32/Silbul.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 18 c1 cb 04 0f cb 89 18 83 fa 04 72 12 8b 5c 02 fc 0f cb c1 c3 04 89 5c 02 fc 83 ea 04 eb e9 } //1
		$a_01_1 = {53 69 6c 76 65 72 6c 69 67 68 74 20 50 6c 75 67 69 6e 27 69 20 62 75 6c 75 6e 61 6d 61 64 } //1 Silverlight Plugin'i bulunamad
		$a_01_2 = {46 34 66 00 38 37 57 00 68 3f 77 00 6f 41 7f 00 68 3f 78 00 68 3d } //1
		$a_01_3 = {62 6c 78 51 62 32 78 70 59 32 6c 6c 63 31 78 54 65 58 4e 30 5a 57 30 69 49 43 39 6d 49 43 39 32 49 45 52 70 63 32 46 69 62 47 56 53 5a 57 64 70 63 33 52 79 65 56 52 76 62 32 78 7a 49 } //1 blxQb2xpY2llc1xTeXN0ZW0iIC9mIC92IERpc2FibGVSZWdpc3RyeVRvb2xzI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}