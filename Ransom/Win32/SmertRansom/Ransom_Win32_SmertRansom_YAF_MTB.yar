
rule Ransom_Win32_SmertRansom_YAF_MTB{
	meta:
		description = "Ransom:Win32/SmertRansom.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 66 6f 6f 64 } //1 --food
		$a_01_1 = {2e 73 6d 65 72 74 } //1 .smert
		$a_01_2 = {5c 52 45 41 44 4d 45 2e 74 78 74 } //1 \README.txt
		$a_01_3 = {79 6f 75 20 67 6f 74 20 66 75 63 6b 65 64 } //1 you got fucked
		$a_01_4 = {6e 6f 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 20 74 68 65 20 66 69 6c 65 73 } //1 no way to recover the files
		$a_01_5 = {77 75 61 75 73 65 72 76 } //1 wuauserv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}