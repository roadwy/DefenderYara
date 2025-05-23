
rule Trojan_Win32_Sefnit_L{
	meta:
		description = "Trojan:Win32/Sefnit.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {67 65 74 74 61 73 6b 73 2e 70 68 70 3f 70 72 6f 74 6f 63 6f 6c 3d ?? 26 70 72 6f 74 6f 76 65 72 73 69 6f 6e 3d } //1
		$a_02_1 = {67 00 65 00 74 00 74 00 61 00 73 00 6b 00 73 00 2e 00 70 00 68 00 70 00 3f 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 3d 00 ?? ?? 26 00 70 00 72 00 6f 00 74 00 6f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 } //1
		$a_03_2 = {5c 6f 75 74 70 75 74 5c 4d 69 6e 53 69 7a 65 52 65 6c 5c (62 6f 74 2e 70 64 62|62 61 63 6b 64 6f 6f 72 2e 70 64 62) } //2
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}