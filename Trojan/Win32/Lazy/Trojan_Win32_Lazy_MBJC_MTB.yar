
rule Trojan_Win32_Lazy_MBJC_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MBJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 61 78 6f 79 78 64 78 69 } //1 raxoyxdxi
		$a_01_1 = {7a 73 6e 76 6e 6a 76 6e 64 71 76 69 } //1 zsnvnjvndqvi
		$a_01_2 = {71 6f 77 72 71 73 6d 62 70 77 } //1 qowrqsmbpw
		$a_01_3 = {66 66 66 6e 6f 67 6b } //1 fffnogk
		$a_01_4 = {65 73 77 62 78 6d 6a 73 7a 69 7a } //1 eswbxmjsziz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}