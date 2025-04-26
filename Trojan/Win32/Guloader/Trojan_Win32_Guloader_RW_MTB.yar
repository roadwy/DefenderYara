
rule Trojan_Win32_Guloader_RW_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 73 79 63 68 6f 61 6e 61 6c 79 7a 65 64 38 } //1 Psychoanalyzed8
		$a_00_1 = {70 00 50 00 30 00 4c 00 78 00 69 00 6b 00 30 00 77 00 75 00 77 00 69 00 67 00 4e 00 68 00 61 00 6e 00 6f 00 56 00 67 00 6e 00 4e 00 46 00 6f 00 34 00 49 00 64 00 37 00 38 00 38 00 71 00 6d 00 33 00 43 00 6e 00 71 00 69 00 31 00 31 00 32 00 } //1 pP0Lxik0wuwigNhanoVgnNFo4Id788qm3Cnqi112
		$a_00_2 = {4d 00 63 00 38 00 61 00 66 00 73 00 46 00 59 00 30 00 5a 00 5a 00 78 00 5a 00 66 00 4f 00 77 00 4d 00 51 00 6a 00 6c 00 4a 00 33 00 51 00 44 00 73 00 68 00 37 00 34 00 79 00 37 00 36 00 36 00 } //1 Mc8afsFY0ZZxZfOwMQjlJ3QDsh74y766
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}