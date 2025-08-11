
rule Trojan_Win32_Midie_SEF_MTB{
	meta:
		description = "Trojan:Win32/Midie.SEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 6f 78 2f 31 68 69 72 65 66 68 30 31 20 46 68 31 30 30 31 68 6f 2f 32 30 68 47 65 63 6b 68 2e 30 29 20 68 76 3a 31 36 68 34 3b 20 72 68 57 4f 57 36 68 2e 31 3b 20 68 4e 54 20 36 68 6f 77 73 20 68 57 69 6e 64 68 2e 30 20 28 68 6c 61 2f 35 68 6f 7a 69 6c 68 } //1 hox/1hirefh01 Fh1001ho/20hGeckh.0) hv:16h4; rhWOW6h.1; hNT 6hows hWindh.0 (hla/5hozilh
		$a_81_1 = {64 75 6d 6d 79 57 69 6e 64 6f 77 43 6c 61 73 73 } //1 dummyWindowClass
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}