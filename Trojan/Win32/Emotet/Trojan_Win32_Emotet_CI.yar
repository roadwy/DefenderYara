
rule Trojan_Win32_Emotet_CI{
	meta:
		description = "Trojan:Win32/Emotet.CI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 53 46 48 45 44 47 48 20 34 35 38 39 00 23 00 24 00 5e 00 54 00 47 00 52 00 23 00 24 00 25 } //1
		$a_01_1 = {33 35 6b 43 38 34 38 43 63 2b 35 56 75 79 4f 75 50 49 37 6d 4c 56 2e 70 64 62 } //1 35kC848Cc+5VuyOuPI7mLV.pdb
		$a_01_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 4c 00 54 00 46 00 49 00 4c 00 38 00 30 00 4e } //1
		$a_01_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 6e 00 65 00 63 00 6b 00 6f } //1
		$a_01_4 = {43 2d 6f 6e 21 69 47 35 45 73 48 77 51 4c 2e 70 64 62 } //1 C-on!iG5EsHwQL.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_CI_2{
	meta:
		description = "Trojan:Win32/Emotet.CI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 56 76 40 70 3d 69 38 71 67 2e 79 6c 51 4a 78 78 21 6c 2e 70 64 62 } //1 3Vv@p=i8qg.ylQJxx!l.pdb
		$a_01_1 = {44 00 65 00 6d 00 6f 00 53 00 68 00 69 00 65 00 6c 00 64 00 20 00 44 00 65 00 73 00 69 00 67 00 6e 00 65 00 72 00 40 00 41 00 20 00 6d 00 61 00 63 00 72 00 6f 00 20 00 69 00 73 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 6c 00 79 00 20 00 62 00 65 00 69 00 6e 00 67 00 20 00 72 00 65 00 63 00 6f 00 72 00 64 00 65 00 64 00 } //1 DemoShield Designer@A macro is currently being recorded
		$a_01_2 = {54 00 68 00 65 00 20 00 6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 69 00 73 00 20 00 63 00 61 00 6e 00 63 00 65 00 6c 00 6c 00 65 00 64 00 } //1 The operation is cancelled
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_CI_3{
	meta:
		description = "Trojan:Win32/Emotet.CI,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 66 66 66 66 66 } //1 PSXPSXPSXPSXPSXPSXfffff
	condition:
		((#a_01_0  & 1)*1) >=1
 
}