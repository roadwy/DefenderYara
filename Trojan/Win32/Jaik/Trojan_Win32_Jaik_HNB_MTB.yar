
rule Trojan_Win32_Jaik_HNB_MTB{
	meta:
		description = "Trojan:Win32/Jaik.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 65 74 50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 61 74 69 6f 6e 00 47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 57 00 00 00 47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 00 00 47 65 74 41 63 74 69 76 65 57 69 6e 64 6f 77 00 4d 65 73 73 61 67 65 42 6f 78 57 00 55 00 53 00 45 00 52 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 00 00 00 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 00 00 00 25 [0-30] 2e 64 61 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}