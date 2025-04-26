
rule Virus_Win32_Memery_HNS_MTB{
	meta:
		description = "Virus:Win32/Memery.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {b9 40 00 00 00 33 c0 8d bc 24 61 02 00 00 88 9c 24 60 02 00 00 f3 ab 66 ab aa } //1
		$a_01_1 = {69 6e 66 65 63 74 20 25 73 0a 00 00 2e 45 58 45 00 00 00 00 2e 65 78 65 00 00 00 00 66 69 6e 64 20 66 69 6c 65 20 66 61 69 6c 65 64 } //1
		$a_01_2 = {6f 70 65 6e 20 66 69 6c 65 20 65 72 72 6f 72 0a 00 00 00 00 6d 61 6c 6c 6f 63 20 6d 65 6d 65 72 79 20 66 61 69 6c 65 64 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=7
 
}