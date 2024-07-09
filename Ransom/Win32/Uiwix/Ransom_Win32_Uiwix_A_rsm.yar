
rule Ransom_Win32_Uiwix_A_rsm{
	meta:
		description = "Ransom:Win32/Uiwix.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 74 69 73 74 69 63 7c 7c } //1 statistic||
		$a_01_1 = {25 25 49 44 25 25 2e 55 49 57 49 58 } //1 %%ID%%.UIWIX
		$a_03_2 = {2e 6f 6e 69 6f 6e 2f [0-10] 2e 70 68 70 3b } //1
		$a_01_3 = {5f 44 45 43 4f 44 45 5f 46 49 4c 45 53 2e 74 78 74 } //1 _DECODE_FILES.txt
		$a_01_4 = {3a 54 4d 65 6d 4d 6f 64 75 6c 65 2e 3a } //1 :TMemModule.:
		$a_00_5 = {2d 31 00 30 00 65 78 70 6c 6f 69 74 00 } //1
		$a_00_6 = {68 66 64 58 72 58 7a 51 42 63 4b 4c 6c 73 72 5a 00 } //1
		$a_01_7 = {0f b6 1a 3a 5d ff 75 08 0f b6 01 88 45 fe eb 07 40 41 42 3c 3e 75 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}