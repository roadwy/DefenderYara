
rule Trojan_BAT_FormBook_RVD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 9d a2 3d 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 b4 00 00 00 27 00 00 00 c3 00 00 00 a4 00 00 00 c0 00 00 00 93 01 00 00 3b 00 00 00 39 00 00 00 01 00 00 00 43 00 00 00 02 00 00 00 04 00 00 00 05 00 00 00 05 00 00 00 06 00 00 00 11 00 00 00 01 00 00 00 01 00 00 00 08 00 00 00 05 00 00 00 10 00 00 00 02 } //1
		$a_81_1 = {36 35 30 31 38 31 38 63 2d 39 35 37 61 2d 34 61 36 30 2d 61 38 38 37 2d 35 65 37 66 64 65 32 64 61 35 32 61 } //1 6501818c-957a-4a60-a887-5e7fde2da52a
		$a_81_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 4f 43 52 } //1 WindowsFormsOCR
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}