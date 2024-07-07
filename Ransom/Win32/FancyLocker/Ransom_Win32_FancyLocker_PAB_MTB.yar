
rule Ransom_Win32_FancyLocker_PAB_MTB{
	meta:
		description = "Ransom:Win32/FancyLocker.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //1 Your files have been encrypted!
		$a_01_1 = {69 6e 66 65 63 74 65 64 20 77 69 74 68 20 46 61 6e 63 79 4c 6f 63 6b 65 72 } //1 infected with FancyLocker
		$a_01_2 = {64 61 74 61 20 77 69 6c 6c 20 67 65 74 20 6c 65 61 6b 65 64 21 } //1 data will get leaked!
		$a_01_3 = {64 72 6f 70 52 61 6e 73 6f 6d 4c 65 74 74 65 72 } //1 dropRansomLetter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}