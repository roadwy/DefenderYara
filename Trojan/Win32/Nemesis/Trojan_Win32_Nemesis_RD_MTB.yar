
rule Trojan_Win32_Nemesis_RD_MTB{
	meta:
		description = "Trojan:Win32/Nemesis.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 61 00 6e 00 64 00 75 00 73 00 6b 00 79 00 20 00 61 00 66 00 73 00 6f 00 6e 00 65 00 6e 00 64 00 65 00 } //1 Sandusky afsonende
		$a_01_1 = {49 00 6e 00 63 00 72 00 65 00 70 00 74 00 20 00 52 00 6f 00 6f 00 73 00 74 00 65 00 64 00 20 00 50 00 41 00 4d 00 50 00 45 00 52 00 45 00 44 00 } //1 Incrept Roosted PAMPERED
		$a_01_2 = {49 00 6d 00 61 00 67 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 73 00 20 00 50 00 6c 00 61 00 6e 00 74 00 6e 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 73 00 } //1 Imaginations Plantningernes
		$a_01_3 = {47 65 74 53 68 6f 72 74 50 61 74 68 4e 61 6d 65 41 } //1 GetShortPathNameA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}