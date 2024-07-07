
rule TrojanSpy_Win32_Downeks_SK_MTB{
	meta:
		description = "TrojanSpy:Win32/Downeks.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {53 65 72 67 65 79 20 4b 6c 6f 75 62 6b 6f 76 } //1 Sergey Kloubkov
		$a_81_1 = {67 69 74 6c 61 62 2e 63 6f 6d 2f 30 63 6f 64 65 72 70 72 6f 64 75 63 74 73 2f 6d 79 61 6e 75 73 2f 2d 2f 72 61 77 2f 6d 61 73 74 65 72 2f 73 74 6f 72 61 67 65 2f 74 65 78 74 2e 74 78 74 } //1 gitlab.com/0coderproducts/myanus/-/raw/master/storage/text.txt
		$a_81_2 = {48 65 75 72 69 73 74 69 63 2e 53 75 73 70 2e 42 61 74 20 28 } //1 Heuristic.Susp.Bat (
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}