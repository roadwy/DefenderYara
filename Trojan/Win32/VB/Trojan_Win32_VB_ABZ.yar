
rule Trojan_Win32_VB_ABZ{
	meta:
		description = "Trojan:Win32/VB.ABZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 37 00 33 00 73 00 2e 00 6e 00 65 00 74 00 2f 00 68 00 74 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 68 00 74 00 6d 00 } //1 .73s.net/ht/index.htm
		$a_03_1 = {2e 00 70 00 61 00 69 00 6e 00 77 00 65 00 62 00 2e 00 6e 00 65 00 74 00 2f 00 68 00 74 00 2f 00 69 00 6e 00 64 00 65 00 78 00 ?? ?? 2e 00 68 00 74 00 6d 00 6c 00 } //1
		$a_01_2 = {66 66 67 66 67 66 67 66 32 00 00 00 66 64 66 66 73 67 66 31 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}