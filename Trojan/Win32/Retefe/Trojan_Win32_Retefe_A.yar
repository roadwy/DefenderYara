
rule Trojan_Win32_Retefe_A{
	meta:
		description = "Trojan:Win32/Retefe.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 63 6b 54 6f 6b 65 6e 4d 65 6d 62 65 72 73 68 69 70 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1
		$a_01_1 = {00 43 45 52 54 5f 49 6d 70 6f 72 74 43 65 72 74 73 00 } //1 䌀剅彔浉潰瑲敃瑲s
		$a_03_2 = {8b 51 04 8b 84 15 90 01 01 ff ff ff a8 06 75 5b 8b 8c 15 90 01 01 ff ff ff 8b 11 8b 52 28 6a 01 6a 02 56 56 8d 45 90 01 01 50 ff d2 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}